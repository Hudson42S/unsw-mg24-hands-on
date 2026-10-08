# UNSW-MG24 hands-on

Two small machine-learning experiments on **UNSW-MG24**, a cybersecurity dataset recorded on a real microgrid testbed at UNSW Canberra.
The goal is not a state-of-the-art detector but a worked example of how to start a project with a new dataset:
read the data card, find the pitfalls, pick a simple baseline, and say honestly what the results do and do not show.

| Notebook | Data | Method | Question |
|---|---|---|---|
| [`01_network_lr_vs_dt.ipynb`](notebooks/01_network_lr_vs_dt.ipynb) | Network flows (CICFlowMeter) | Logistic regression vs decision tree | Can flow statistics tell attacks apart? Where does a linear model fall short? |
| [`02_power_linear_regression.ipynb`](notebooks/02_power_linear_regression.ipynb) | Power measurements | Linear regression on normal data + residual alarms | Do the attacks leave a physical trace on the equipment? |

Both notebooks are committed **with their outputs**, so you can read the results on GitHub before running anything.

## The dataset

- Page: <https://ieee-dataport.org/documents/unsw-mg24> (DOI [10.21227/q9td-3f09](https://doi.org/10.21227/q9td-3f09))
- Paper: Z. Zhang et al., "UNSW-MG24: A Heterogeneous Dataset for Cybersecurity Analysis in Realistic Microgrid Systems", *IEEE Open Journal of the Computer Society*, vol. 6, pp. 543–553, 2025, doi:[10.1109/OJCS.2025.3564266](https://doi.org/10.1109/OJCS.2025.3564266)
- License: [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)

The dataset contains three kinds of data, all captured while 10 types of attack (DoS, DDoS, scan, password guessing, SQL injection, backdoor, …) were run against the microgrid network:

- **Network traffic**: packet captures converted to flow records with CICFlowMeter (one row per connection, ~80 statistics)
- **System-call traces** of the victim hosts (not used in these notebooks)
- **Power measurements** from two pieces of equipment in a Festo LabVolt microgrid: a dynamometer (motor shaft speed, torque, power) and a DC chopper (bus voltage, current, power)

This repository does **not** include the dataset. It assumes you already have the original UNSW-MG24 folders
(if you do not, they are on the [IEEE DataPort page](https://ieee-dataport.org/documents/unsw-mg24)).

## Repository layout

```
unsw-mg24-hands-on/
├── notebooks/
│   ├── 01_network_lr_vs_dt.ipynb
│   ├── 02_power_linear_regression.ipynb
│   └── common.py              # paths and chart style shared by the notebooks
├── scripts/
│   └── build_dataset.py       # data/<dataset folders> -> data/processed/ (labels, cleaning, data card)
├── data/                      # put the dataset folders here; ignored by git, see data/README.md
└── requirements.txt
```

## 1. Set up Python

Python 3.10 or newer.

```bash
git clone https://github.com/Hudson42S/unsw-mg24-hands-on.git
cd unsw-mg24-hands-on
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Put the dataset into `data/` and build

Copy the extracted UNSW-MG24 folders directly into `data/`:

```
data/
├── Benign network traffic/
├── Synthetic benign network traffic/
├── Power measurement/
├── backdoor/  ddos/  dos/  MITM/  password/  ransomware/  samba+permission/  scan/  shellshock/  sql/
├── Benign system call traces/       # optional
└── Malicious system call traces/    # optional
```

Keep the folder names exactly as they are in the dataset. The system-call folders are only used for a summary in the data card; `CICFlowMeter-4.0` is not used.
[`data/README.md`](data/README.md) explains what each folder holds and how to read the raw files.
Everything in `data/` is ignored by git, so the dataset is never committed by accident.

Then build the processed tables:

```bash
python scripts/build_dataset.py
```

The script labels the flows, cleans the power CSVs and writes everything to `data/processed/`, together with a data card, `data/processed/README.md`, that documents every column and the labelling rule.
If a folder is missing or empty, it tells you which one. You only need to run it once.

## 3. Run the notebooks

```bash
jupyter lab
```

Open `notebooks/` and run each notebook from top to bottom (*Run → Run All Cells*). Figures are also saved to `figures/`.

**Resources:** building the dataset and running notebook 1 each need **up to 6 GB of RAM** (the flow table has 2.7 million rows), so a machine with 16 GB is recommended; on 8 GB, close other programs first. Notebook 2 is tiny. Building adds about 200 MB (`data/processed/`) on top of the dataset itself. On a laptop, each step takes a few minutes at most.

## What you should see

Results from the committed run (Python 3.11, pandas 3.0, scikit-learn 1.9). The logistic-regression numbers shift by about a point between scikit-learn versions (with scikit-learn 1.3, for example, LR macro-F1 is 0.69 and its false positive rate on real benign traffic 3.5%); everything else is reproducible and the conclusions are the same.

**Notebook 1: network flows**

| | LR | LR + log | DT |
|---|---:|---:|---:|
| Binary F1 (benign vs attack) | 0.9992 | 0.9998 | 0.9999 |
| Multi-class macro-F1 (7 classes) | 0.68 | 0.88 | 0.91 |
| False positive rate on *real* benign traffic | 4.44% | 1.51% | 0.38% |
| False positive rate on *synthetic* benign traffic | 0.01% | 0.00% | 0.01% |

- 2,676,964 flows shrink to 380,040 after removing duplicates; the 2.23 million DDoS flows have only 89 distinct feature vectors.
- Logistic regression labels 96% of DDoS flows as port scans; the decision tree separates them.

**Notebook 2: power measurements**

- DC chopper: the fitted slope is 74.85 W/A, i.e. the 75 V bus voltage. Residual alarms fire on 5.6% of the attack recording vs 0.4% of the normal hold-out, and 49 of the 51 attack alarms fall on 60 V voltage sags.
- Dynamometer: the slope corresponds to 1498 rpm (rated 1500 rpm), R² ≈ 1, and there are no alarms under attack.
- The notebook also explains why the DC chopper result is close to trivial (power is computed as V × I) and why only alarm rates, not precision and recall, can be reported.

## Things to know about this dataset

These come up in the notebooks; they matter for any project you build on UNSW-MG24.

- **Duplicates:** the DDoS capture is millions of identical single-packet flows. Deduplicate before splitting, or the test set leaks into training.
- **Mostly synthetic benign traffic:** 98.5% of the benign flows were generated with Scapy; only 3,616 come from the real microgrid lab. Report performance on the real ones separately.
- **Leaky columns:** IP addresses, ports, Flow ID and timestamps identify the attacker and the capture day. Drop them. In the power data, the cumulative `energy_wh` column leaks the recording.
- **Labels:** the flow CSVs ship without attack labels; `build_dataset.py` assigns them by victim IP (rule in the data card). Flows in attack captures that do not involve a victim are labelled `background`.
- **Power labels are per recording:** each device has one normal and one malicious recording, with no information on when an attack was running.

## Citation

If you use the dataset, cite both the dataset and the paper:

```bibtex
@misc{zhang2025unswmg24data,
  author    = {Zhang, Zhibo and Turnbull, Benjamin and Kasra, Shabnam and Pota, Hemanshu and Hu, Jiankun},
  title     = {{UNSW-MG24}},
  publisher = {IEEE Dataport},
  year      = {2025},
  doi       = {10.21227/q9td-3f09},
  url       = {https://ieee-dataport.org/documents/unsw-mg24}
}

@article{zhang2025unswmg24,
  author  = {Zhang, Zhibo and Turnbull, Benjamin and Kasra Kermanshahi, Shabnam and Pota, Hemanshu and Hu, Jiankun},
  title   = {{UNSW-MG24}: A Heterogeneous Dataset for Cybersecurity Analysis in Realistic Microgrid Systems},
  journal = {IEEE Open Journal of the Computer Society},
  volume  = {6},
  pages   = {543--553},
  year    = {2025},
  doi     = {10.1109/OJCS.2025.3564266}
}
```

## License

The dataset is © its authors and licensed under CC BY 4.0; it is not redistributed here. The code in this repository is released under the license in [`LICENSE`](LICENSE).
