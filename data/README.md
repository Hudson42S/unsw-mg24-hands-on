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
