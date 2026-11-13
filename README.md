<div align="center">
  <img src="logo.png" alt="MR CYBER PULSE logo" width="400" />
</div>

<h1 align="center">IoT Hunter </h1>

<p align="center">
  <strong>Defensive IoT Security Toolkit</strong><br>
  <i>Device Discovery · Service Fingerprinting · TLS Hygiene · Remediation Guidance · Reporting</i>
</p>

<p align="center">
  <a href="https://github.com/mrcyberharsh/iot-hunter/stargazers">
    <img src="https://img.shields.io/github/stars/mrcyberharsh/iot-hunter?style=for-the-badge&logo=github&color=blue" alt="GitHub stars" />
  </a>
  <a href="https://github.com/mrcyberharsh/iot-hunter/issues">
    <img src="https://img.shields.io/github/issues/mrcyberharsh/iot-hunter?style=for-the-badge&logo=github&color=red" alt="Issues" />
  </a>
  <a href="https://github.com/mrcyberharsh/iot-hunter/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/mrcyberharsh/iot-hunter?style=for-the-badge&logo=gnu&color=green" alt="License" />
  </a>
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  </a>
  <a href="https://github.com/mrcyberharsh/iot-hunter/pulls">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen?style=for-the-badge" alt="PRs Welcome" />
  </a>
</p>

---

**IoT Hunter** is a defensive toolkit for inventorying and reviewing IoT devices on networks you own or are authorized to assess. The current development branch identifies itself as **v3.1**.

> ⚠️ **Disclaimer:** Findings are **leads for review**, not proof of exploitability. Some checks depend on operating-system permissions, network visibility, and optional system packages.

## ✨ Capabilities

-  **Local-network Discovery:** Active scanning and device inventorying.
-  **Fingerprinting:** Service, banner, and vendor identification (OUI lookup).
-  **Vulnerability Lookup:** CVE information based on detected services.
-  **TLS / Certificate Hygiene:** Expiry, weak ciphers, and self-signed cert detection.
-  **Protocol Review:** Configuration checking for IoT protocols.
-  **Reporting:** PDF and JSON generation with inventory change summaries.
-  **History Tracking:** Local snapshots with new, missing, and changed-device tracking.
-  **Safe by Default:** Private IPv4 range limits, explicit authorization confirmation, and no default credential guessing.

##  Requirements

- **Python** 3.10+
- Dependencies in [`requirements.txt`](requirements.txt)
- Optional platform support packages (Npcap for Windows, libpcap for Linux/macOS)

##  Installation

Clone the repository and install its Python dependencies:

```bash
git clone https://github.com/mrcyberharsh/iot-hunter.git
cd iot-hunter
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

### 🐧 Linux
Install the system packages required by network interfaces and packet-capture features:
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev python3-tk libpcap-dev
```

###  Windows
1. Install Python 3.10 or newer.
2. Install [Npcap](https://npcap.com/) (required for packet-capture).
3. Open PowerShell and install the Python dependencies.

###  macOS
Install Python and the required packet-capture support through trusted package sources, then install the Python dependencies.

##  Launch

**CLI Mode:**
```bash
python iothunter.py
```

**GUI Mode:**
```bash
python gui.py
```

*The full scan records local inventory snapshots at `data/inventory-history.json` (local-only, excluded from Git). The default workflow does not perform credential guessing.*

## 📂 Repository Layout

```text
iot-hunter/
├── gui.py
├── iothunter.py
├── config.yaml
├── requirements.txt
├── modules/
│   ├── anomaly.py
│   ├── credentials.py
│   ├── discovery.py
│   ├── fingerprint.py
│   ├── protocol.py
│   ├── remediation.py
│   └── reporting.py
├── reports/
└── logs/
```

##  Inventory History

Each full scan stores a compact snapshot containing IP address, MAC address, vendor, hostname, device type, and observed open ports. The next run compares the current inventory with the previous snapshot and reports newly observed, missing, and changed devices. 

- History is capped at **50 snapshots**.
- Review the local history file carefully before sharing it because it contains internal network metadata.

## Understanding Results

- **Service banners** and version strings can be inaccurate or intentionally obscured.
- **CVE search results** may include false positives; verify product, version, and vendor advisories.
- **Anomaly alerts** are indicators that need context from a network administrator.
- **Reports** should be reviewed before sharing because they may contain internal host and service details.

##  Authorization & Safe Operation

Use IoT Hunter **only** on devices and private networks you own or have explicit written permission to assess. 

- The desktop scanner asks for authorization confirmation.
- Manually entered ranges are limited to private IPv4 networks up to `/24`.
- The default workflow skips credential guessing.
- **Do not** attempt to access accounts, disrupt devices, or test third-party networks without authorization.

## 🤝 Contributing

Issues and pull requests are welcome! 
Please check out our **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** before submitting.
Never publish credentials, private IP inventories, packet captures, or other sensitive network data in public issues.

##  Author & License

Created by **Harsh Saini · MR Cyber Pulse**.

- **GitHub:** [@mrcyberharsh](https://github.com/mrcyberharsh)
- **Project:** [iot-hunter](https://github.com/mrcyberharsh/iot-hunter)
- **Contact:** cyber.h4rsh@zohomail.in

Licensed under **GNU GPL-3.0**. See [`LICENSE`](LICENSE) for details.
