"""Build analysis-ready UNSW-MG24 tables from the dataset folders in data/.

Put the extracted UNSW-MG24 folders ("Benign network traffic", "ddos", "Power measurement", ...)
directly into data/, then run

    python scripts/build_dataset.py

Outputs (data/processed/):
    network_flows.parquet        CICFlowMeter flows (benign + attack captures), labelled
    network_campus_base.parquet  campus base traffic used to synthesise benign flows (other extractor/schema)
    power_local1.csv             local controller 1: dynamometer speed / torque / power
    power_local2.csv             local controller 2: chopper DC side + 3 scope channels
    syscall_summary.csv          event counts per system call trace file
    README.md                    data card with counts and labelling rules

The network and power folders are required; the system-call folders are optional.
"""

import re
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data"
OUT = RAW / "processed"

# ---------------------------------------------------------------- network flows

# Attack captures also contain the capturing hosts' own traffic (GNS3 API on
# 192.168.4.71:3080, GNS3 UDP tunnels, DNS, NTP, Ubiquiti discovery, HTTPS to the
# internet). Only flows that reach a victim VM are attack traffic. 192.168.4.191,
# .192 and .249 are the victims observed in the captures; .102-.106 are the
# victim VMs listed in the paper.
VICTIM_IPS = {"192.168.4.191", "192.168.4.192", "192.168.4.249"} | {f"192.168.4.{i}" for i in range(102, 107)}
GATEWAY_IP = "192.168.4.1"

ATTACK_LABELS = {
    "backdoor": "backdoor",
    "ddos": "ddos",
    "dos": "dos",
    "MITM": "mitm",
    "password": "password",
    "ransomware": "ransomware",
    "samba+permission": "samba_permission",
    "scan": "scan",
    "shellshock": "shellshock",
    "sql": "sql_injection",
}

DEPARTMENTS = {"admin": "admin", "microgrid": "microgrid", "research": "research", "teaching": "teaching"}
ORIGINAL_BENIGN = "microgrid department network traffic/microgrid traffic.csv"  # the real (non-synthetic) benign capture


def department_of(path):
    folder = path.parent.name.lower()
    return next(v for k, v in DEPARTMENTS.items() if folder.startswith(k))


def parse_cic_timestamp(s):
    # CICFlowMeter was run on a Chinese-locale machine: 上午 = AM, 下午 = PM.
    s = s.astype(str).str.replace("上午", "AM", regex=False).str.replace("下午", "PM", regex=False)
    return pd.to_datetime(s, format="%d/%m/%Y %I:%M:%S %p", errors="coerce")


def read_cic(path):
    df = pd.read_csv(path, low_memory=False)
    df = df[df["Label"] != "Label"]  # repeated header rows, if any
    df = df.drop(columns=["Label"])  # always "No Label"
    meta = {"Flow ID", "Src IP", "Dst IP", "Timestamp"}
    for col in df.columns.difference(list(meta)):
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df["Timestamp"] = parse_cic_timestamp(df["Timestamp"])
    return df.replace([np.inf, -np.inf], np.nan)


def is_broadcast_or_multicast(ip):
    return ip.str.endswith(".255") | ip.str.match(r"^(22[4-9]|23\d)\.")


def attack_mask(df):
    src_victim = df["Src IP"].isin(VICTIM_IPS)
    dst_victim = df["Dst IP"].isin(VICTIM_IPS)
    other = df["Dst IP"].where(src_victim, df["Src IP"])
    # Only the destination is checked for broadcast/multicast: DDoS source IPs are
    # spoofed at random, and ~6% of them fall in those ranges by chance.
    return (src_victim | dst_victim) & (other != GATEWAY_IP) & ~is_broadcast_or_multicast(df["Dst IP"])


def build_network():
    frames = []

    for path in sorted(RAW.glob("Synthetic benign network traffic/*/*.csv")):
        df = read_cic(path)
        df["label"], df["source"], df["department"] = "benign", "synthetic_benign", department_of(path)
        df["capture"] = path.name.removesuffix(".pcap_Flow.csv")
        frames.append(df)

    df = read_cic(RAW / "Benign network traffic" / ORIGINAL_BENIGN)
    df["label"], df["source"], df["department"], df["capture"] = "benign", "original_benign", "microgrid", "microgrid_traffic"
    frames.append(df)

    for folder, label in ATTACK_LABELS.items():
        for path in sorted((RAW / folder).glob("*.pcap_Flow.csv")):
            df = read_cic(path)
            df["label"] = np.where(attack_mask(df), label, "background")
            df["source"], df["department"] = "attack_capture", pd.NA
            df["capture"] = path.name.removesuffix(".pcap_Flow.csv")
            frames.append(df)

    flows = pd.concat(frames, ignore_index=True)
    flows["is_attack"] = (~flows["label"].isin(["benign", "background"])).astype("int8")
    for col in ["label", "source", "department", "capture"]:
        flows[col] = flows[col].astype("category")
    return flows


def build_campus_base():
    frames = []
    for path in sorted(RAW.glob("Benign network traffic/*/*.csv")):
        if "microgrid" in path.parent.name:
            continue
        df = pd.read_csv(path, low_memory=False)
        # The file's own label column is unreliable (research traffic is labelled "Admin").
        df = df.drop(columns=["label"]).copy().assign(department=department_of(path))
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------- power

# local2 CSVs list 17 headers but only 14 values per row: Duty Cycle and the
# acceleration/deceleration times are not exported. The order below was verified
# with P = V * I (corr = 1.0) and the cumulative energy column.
LOCAL1_COLS = ["speed_rpm", "torque_nm", "power_w", "energy_wh"]
LOCAL2_COLS = [
    "switching_freq_hz", "voltage_v", "current_a", "power_w", "energy_wh",
    "ch1_rms_v", "ch1_avg_v", "ch1_freq_hz",
    "ch2_rms_v", "ch2_avg_v", "ch2_freq_hz",
    "ch3_rms_v", "ch3_avg_v", "ch3_freq_hz",
]


def read_power(path, cols):
    df = pd.read_csv(path, skiprows=3, header=None).dropna(axis=1, how="all").dropna(how="all")
    assert df.shape[1] == len(cols), f"{path.name}: expected {len(cols)} columns, got {df.shape[1]}"
    df.columns = cols
    return df.reset_index(drop=True)


def build_power(device, cols):
    frames = []
    for condition in ["normal", "malicious"]:
        df = read_power(RAW / "Power measurement" / f"{device}_{condition}.csv", cols)
        df.insert(0, "t", range(len(df)))  # sample index; the export has no timestamps
        df["condition"], df["is_attack"] = condition, int(condition == "malicious")
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------- system calls

PROCMON_RECORD = re.compile(r'^"\d{1,2}:\d{2}:\d{2}')

def build_syscall_summary():
    rows = []
    for condition in ["Benign", "Malicious"]:
        for path in sorted((RAW / f"{condition} system call traces").rglob("*")):
            suffix = path.suffix.lower()
            if not path.is_file() or suffix not in (".log", ".csv"):
                continue  # XSS.txt / ransomware.txt are attack payloads, .PML files are Procmon binaries
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                lines = fh.readlines()
            if suffix == ".log":
                n = sum(1 for line in lines if line.startswith("type=SYSCALL"))
                tool = "auditd (Linux VM)"
            else:
                # Every Procmon record starts with its quoted time of day. Some exports
                # are followed by binary garbage, which is not counted.
                n = sum(1 for line in lines if PROCMON_RECORD.match(line))
                tool = "Procmon (Windows controller)"
            group = path.parent.name.replace(" department", "").lower() if condition == "Benign" else None
            if group is None:
                group = re.sub(r"(_?\d+)?$", "", path.stem.removeprefix("audit_")).lower()
            rows.append({"condition": condition.lower(), "group": group, "tool": tool,
                         "file": path.name, "n_events": n})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------- inputs

# Folder -> a file it must contain. The system-call folders are optional.
REQUIRED = {
    "Benign network traffic": ORIGINAL_BENIGN,
    "Synthetic benign network traffic": "*/*.pcap_Flow.csv",
    "Power measurement": "local2_malicious.csv",
    **{folder: "*.pcap_Flow.csv" for folder in ATTACK_LABELS},
}


def check_inputs():
    missing = [f"data/{folder}/" for folder, marker in REQUIRED.items() if not any((RAW / folder).glob(marker))]
    if missing:
        raise SystemExit("These UNSW-MG24 folders are missing or empty. Put the extracted dataset folders into data/:\n  "
                         + "\n  ".join(missing))


# ---------------------------------------------------------------- data card

def md_table(df):
    cols = [str(c) for c in df.columns]
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for row in df.itertuples(index=False):
        lines.append("| " + " | ".join(f"{v:,}" if isinstance(v, (int, np.integer)) else str(v) for v in row) + " |")
    return "\n".join(lines)


def write_readme(flows, campus, p1, p2, sys_summary):
    by_label = (flows.groupby(["source", "label"], observed=True).size()
                .rename("flows").reset_index().sort_values(["source", "flows"], ascending=[True, False]))
    benign_dept = (flows[flows["label"] == "benign"].groupby(["source", "department"], observed=True)
                   .size().rename("flows").reset_index())
    power = pd.concat([
        p.groupby("condition").size().rename("rows").reset_index().assign(device=name)
        for name, p in [("local1", p1), ("local2", p2)]
    ])[["device", "condition", "rows"]]
    if sys_summary.empty:
        sys_text = "The system-call folders were not found in data/, so this summary was skipped."
    else:
        sys_tot = (sys_summary.groupby(["condition", "tool"])
                   .agg(files=("file", "size"), events=("n_events", "sum")).reset_index())
        sys_text = md_table(sys_tot)
    ch_same = bool((p2["ch2_rms_v"] == p2["ch3_rms_v"]).all() and (p2["ch2_freq_hz"] == p2["ch3_freq_hz"]).all())

    text = f"""# UNSW-MG24 processed data

Built by `scripts/build_dataset.py` from the original UNSW-MG24 folders in `data/`.

## network_flows.parquet

{len(flows):,} CICFlowMeter-4.0 flows, original 83 feature columns plus:

- `label`: `benign`, an attack name, or `background`
- `is_attack`: 1 for attack labels, 0 for `benign` and `background`
- `source`: `synthetic_benign` (Scapy-generated department traffic), `original_benign` (microgrid lab capture), `attack_capture`
- `department`: admin / microgrid / research / teaching (benign flows only)
- `capture`: originating pcap file

{md_table(by_label)}

Benign flows by department:

{md_table(benign_dept)}

**Labelling rule.** The CSVs ship with `Label = "No Label"`. In attack captures, a flow is labelled with the
capture's attack only if one endpoint is a victim VM ({", ".join(sorted(VICTIM_IPS))}), the other endpoint
is not the gateway, and the destination is not a broadcast or multicast address. All other flows in attack captures (GNS3 API/tunnel
traffic between 192.168.4.200 and 192.168.4.71, DNS, NTP, HTTPS to the internet, discovery broadcasts) are
labelled `background`. Exclude them, or treat them as benign, depending on the experiment.

**Notes.**
- `Timestamp` is parsed from the Chinese-locale CICFlowMeter output (上午/下午 = AM/PM). ±inf values are stored as NaN.
- IP addresses, ports, Flow ID and Timestamp identify the attacker/victim directly. Drop them before training.
- DDoS flows are spoofed-source, mostly single-packet flows and make up most of the attack class.
- Attacks routed through the pivot appear only as a few direct flows (backdoor, ransomware, samba_permission, shellshock, mitm).

## network_campus_base.parquet

{len(campus):,} flows of 2019 campus traffic (admin / research / teaching) that the authors used as base traffic for
synthesising benign flows. They were extracted with a different tool ({campus.shape[1] - 1} snake_case features), so they
cannot be stacked with `network_flows`. The original `label` column was dropped because research traffic is labelled "Admin".

## power_local1.csv / power_local2.csv

{md_table(power)}

- `t` is the sample index within each recording; the export has no timestamps. Rows are in time order.
- local1 (LV8960 dynamometer): `speed_rpm`, `torque_nm`, `power_w`, `energy_wh` (P = T·ω holds exactly).
- local2: chopper DC side (`switching_freq_hz`, `voltage_v`, `current_a`, `power_w`, `energy_wh`) and three scope
  channels (RMS / AVG / frequency). The raw CSV header lists 17 columns but rows hold 14 values: Duty Cycle and
  the acceleration/deceleration times were not exported. Column order was verified with P = V·I.
- Channel 2 and channel 3 are {"identical in every row" if ch_same else "not identical"}.
- `energy_wh` is cumulative and the malicious recording continues where the normal one ends, so it leaks the label.
  Do not use it as a feature.

## syscall_summary.csv

{sys_text}

Per-file counts are in the CSV. `XSS.txt` and `ransomware.txt` are attack payload scripts, not traces.
`local1_normal_system_calls.CSV` and `local2_normal_system_calls.CSV` turn into binary garbage after their first
96,000 and 39,124 records; only intact records are counted.
"""
    (OUT / "README.md").write_text(text)


def main():
    check_inputs()

    OUT.mkdir(parents=True, exist_ok=True)

    print("network flows ...")
    flows = build_network()
    flows.to_parquet(OUT / "network_flows.parquet", index=False)

    print("campus base traffic ...")
    campus = build_campus_base()
    campus.to_parquet(OUT / "network_campus_base.parquet", index=False)

    print("power ...")
    p1, p2 = build_power("local1", LOCAL1_COLS), build_power("local2", LOCAL2_COLS)
    p1.to_csv(OUT / "power_local1.csv", index=False)
    p2.to_csv(OUT / "power_local2.csv", index=False)

    print("system calls ...")
    sys_summary = build_syscall_summary()
    sys_summary.to_csv(OUT / "syscall_summary.csv", index=False)

    write_readme(flows, campus, p1, p2, sys_summary)
    print(f"done -> {OUT}")


if __name__ == "__main__":
    main()
