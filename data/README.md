# data/

Put the extracted UNSW-MG24 dataset folders here, with their original names:

```
data/
├── Benign network traffic/
├── Synthetic benign network traffic/
├── Power measurement/
├── backdoor/  ddos/  dos/  MITM/  password/  ransomware/  samba+permission/  scan/  shellshock/  sql/
├── Benign system call traces/       # optional
├── Malicious system call traces/    # optional
└── processed/                       # written by scripts/build_dataset.py
    ├── network_flows.parquet
    ├── network_campus_base.parquet
    ├── power_local1.csv
    ├── power_local2.csv
    ├── syscall_summary.csv
    └── README.md                    # data card: columns, row counts, labelling rule
```

Everything in this folder except this file is ignored by git.

`scripts/build_dataset.py` already turns the network and power files into clean tables, so you do not need the rest of
this page to run the notebooks. Read on when you want to open the raw files yourself, for example for a project on the
system calls.

## What each folder holds

The release is 15 archives plus the CICFlowMeter tool; each archive unpacks into one folder.

| Folder | What's inside | Files |
|---|---|---|
| `Synthetic benign network traffic` | Synthetic benign traffic of the four department VMs, generated with Scapy. One subfolder per department, one file per VM; the file name is the VM's IP | 15 × `<IP>.pcap_Flow.csv` |
| `Benign network traffic` | `microgrid traffic.csv`: real traffic captured in the microgrid lab. `admin` / `research` / `teaching traffic.csv`: campus traffic the authors used as the base for the synthetic traffic | 4 × `.csv` |
| `backdoor`, `ddos`, `dos`, `MITM`, `password`, `ransomware`, `samba+permission`, `scan`, `shellshock`, `sql` | One attack run each: the raw packet capture and the flow table CICFlowMeter made from it | 1–2 × (`.pcap` + `.pcap_Flow.csv`) |
| `Benign system call traces` | One subfolder per department. Admin, research and teaching hold auditd logs of Linux VMs; microgrid holds Process Monitor (Procmon) records of the three controller PCs (central, local1, local2) | 11 × `.log`, 3 × `.CSV`, 3 × `.PML` |
| `Malicious system call traces` | auditd logs per attack (including two mimicry attacks), Procmon records of the controllers, and two attack payloads | 26 × `.log`, 3 × `.CSV`, 3 × `.PML`, 2 × `.txt` |
| `Power measurement` | Benign and attack recordings of local1 (dynamometer) and local2 (DC chopper) | 4 × `.csv`, 4 × `.tbl` |
| `CICFlowMeter-4.0.rar` | The Java tool that turns pcap files into flow tables | not needed |

Some file names contain typos (`macilious`, `macilous`, `noraml`, `passowrd`, `samaba`). They are in the original
release, so use them as they are.

## Reading the raw files

All snippets assume you run Python from the repository root.

### Network flows: `*.pcap_Flow.csv` and `microgrid traffic.csv`

One row is one flow (the packets exchanged between two endpoints on one connection) and there are 84 columns: seven
identifiers (`Flow ID`, `Src IP`, `Src Port`, `Dst IP`, `Dst Port`, `Protocol`, `Timestamp`), 76 statistics, and `Label`.

- `Label` is `No Label` in every file. You have to assign labels yourself; `build_dataset.py` does it by victim IP
  (see `data/processed/README.md`).
- `Timestamp` was written on a Chinese-locale machine: AM/PM appear as 上午/下午, and dates are day/month/year.
- Times (`Flow Duration`, the IAT columns) are in microseconds. Rates such as `Flow Byts/s` can be infinite for
  single-packet flows. `Protocol` 6 is TCP and 17 is UDP.

```python
import pandas as pd

flows = pd.read_csv("data/sql/sql_injection.pcap_Flow.csv")
ts = flows["Timestamp"].str.replace("上午", "AM").str.replace("下午", "PM")
flows["Timestamp"] = pd.to_datetime(ts, format="%d/%m/%Y %I:%M:%S %p")
```

### Campus base traffic: `admin` / `research` / `teaching traffic.csv`

These come from a different flow extractor: 347 snake_case columns (`duration`, `packets_count`, `payload_bytes_mean`,
...), so they cannot be stacked with the CICFlowMeter tables. The paper cites a Tsinghua University campus traffic
dataset for them; the timestamps are from January–February 2019, and the files hold exactly 5,000, 10,000 and 35,012
flows, so they look like samples. Their `label` column is unreliable (research traffic is labelled `Admin`).

### Raw packets: `*.pcap`

The original captures. Open them in Wireshark if you want to look at individual packets; the notebooks only use the
flow tables.

### System calls: auditd logs (`*.log`)

One line is one record. A `type=SYSCALL` line is one system call; the `PATH`, `CWD` and `EXECVE` lines with the same
`msg=audit(<time>:<serial>)` add details about the same event (file touched, working directory, command line).

```text
type=SYSCALL msg=audit(1732262963.288:2274767): arch=40000003 syscall=3 success=no exit=-11 ... pid=4844 uid=109 comm="mysqld" exe="/usr/sbin/mysqld"
```

- The number inside `audit(...)` is Unix time in seconds (UTC).
- `arch=40000003` means 32-bit x86, so read `syscall=` with the 32-bit (i386) table: 3 = read, 5 = open, 6 = close,
  240 = futex.
- `comm` is the program name, `exe` the executable path, `success` and `exit` the outcome.
- Labels are per file: everything in a malicious log belongs to that attack run, including unrelated background activity.

```python
import re
import pandas as pd

rows = []
with open("data/Malicious system call traces/mimicry1.log", errors="replace") as fh:
    for line in fh:
        if line.startswith("type=SYSCALL"):
            rows.append({k: v.strip('"') for k, v in re.findall(r'(\w+)=("[^"]*"|\S+)', line)})
calls = pd.DataFrame(rows)
calls["time"] = pd.to_datetime(calls["msg"].str.extract(r"audit\(([\d.]+):")[0].astype(float), unit="s")
calls["syscall"] = calls["syscall"].astype(int)
```

### System calls: Procmon records (`*.CSV`, `*.PML`)

The controller PCs run Windows, so their activity was recorded with Process Monitor. The CSVs have seven columns
(`Time of Day`, `Process Name`, `PID`, `Operation`, `Path`, `Result`, `Detail`) and a time of day but no date. Each file
follows one control program (`ScadaApplication.exe` on central, `LVDacEms.exe` on local1); most operations are TCP
send/receive and registry queries. The `.PML` files are Procmon's own binary format and open only in Process Monitor.

`local1_normal_system_calls.CSV` and `local2_normal_system_calls.CSV` turn into binary garbage after about 96,000 and
39,124 records. Keep only rows that start with a time:

```python
pm = pd.read_csv("data/Benign system call traces/Microgrid department/local1_normal_system_calls.CSV",
                 encoding="utf-8-sig", encoding_errors="replace", on_bad_lines="skip", engine="python")
pm = pm[pm["Time of Day"].astype(str).str.match(r"\d{1,2}:\d{2}:\d{2}")]
```

### Power measurements (`*.csv`, `*.tbl`)

The CSVs were exported from the LabVolt LVDAC-EMS software. The first three lines are the column names, an empty line
and the units; values start on line 4. There is no time column: row order is time order.

- local1 (dynamometer): speed (r/min), torque (N·m), power (W), cumulative energy (W·h). The trailing columns are empty.
- local2 (DC chopper): the header lists 17 columns but each row holds 14 values, because duty cycle and the
  acceleration/deceleration times were not exported. The headers therefore do not line up with the values; for
  example, the numbers under `Duty-Cycle-[Q1]-` are actually the bus voltage. The order below was checked with P = V × I.
- Energy is cumulative, so the benign and attack recordings cover different value ranges. Do not use it as a feature.
- The `.tbl` files are the same tables in LVDAC-EMS's binary format; they hold no timestamps either.

```python
p2 = pd.read_csv("data/Power measurement/local2_normal.csv", skiprows=3, header=None).dropna(axis=1, how="all")
p2.columns = ["switching_freq_hz", "voltage_v", "current_a", "power_w", "energy_wh",
              "ch1_rms_v", "ch1_avg_v", "ch1_freq_hz", "ch2_rms_v", "ch2_avg_v", "ch2_freq_hz",
              "ch3_rms_v", "ch3_avg_v", "ch3_freq_hz"]
```

### Attack payloads: `XSS.txt`, `ransomware.txt`

Not traces but the scripts used in the attacks: an XSS payload that sends the victim's cookies to 192.168.4.201:8080,
and a bash script that encrypts files with openssl and deletes the originals.

## Key IP addresses

The paper's description and the files do not always agree; trust what you see in the files.

| IP | Role | Source |
|---|---|---|
| 192.168.4.200 | Attacking Windows 11 PC | paper |
| 192.168.4.201 | Kali VM on that PC (inside attacker); apart from the spoofed DDoS and MITM, almost every attack flow comes from here | paper, captures |
| 192.168.4.202 | Outside Kali attacker of the pivoting scenario | paper; not in any capture |
| 192.168.4.71 | GNS3 emulator VM; its management traffic with .200 is mixed into the attack captures | paper, captures |
| 192.168.4.99 | Central controller (SCADA) | paper |
| 192.168.4.100–101 | Local controllers (OPC UA servers) | paper |
| 192.168.4.102–106 | Victim VMs (OWASP Security Shepherd, Metasploitable3) | paper; only .106 appears, in 2 DoS flows |
| 192.168.4.191, .192, .249 | Hosts actually attacked in the captures | captures; not in the paper |
| 192.168.6.x, 3.x, 5.x, 2.x | Admin, teaching, research and microgrid-lab VMs of the synthetic traffic | file names; the paper lists admin as 2.x and microgrid as 3.x |
