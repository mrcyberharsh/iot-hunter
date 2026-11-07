# IoT Hunter

<div align="center">
  <img src="assets/mr-cyber-pulse-logo.svg" alt="MR CYBER PULSE logo" width="520" />
</div>

<p align="center">
  <strong>Defensive IoT Security Toolkit</strong><br>
  Device discovery · Service fingerprinting · Protocol review · Anomaly monitoring · Remediation guidance · Reporting
</p>

<p align="center">
  <a href="https://github.com/mrcyberharsh/iot-hunter/stargazers"><img src="https://img.shields.io/github/stars/mrcyberharsh/iot-hunter?style=flat-square" alt="GitHub stars" /></a>
  <a href="https://github.com/mrcyberharsh/iot-hunter/issues"><img src="https://img.shields.io/github/issues/mrcyberharsh/iot-hunter?style=flat-square" alt="Issues" /></a>
  <a href="https://github.com/mrcyberharsh/iot-hunter/blob/main/LICENSE"><img src="https://img.shields.io/github/license/mrcyberharsh/iot-hunter?style=flat-square" alt="License" /></a>
</p>

**IoT Hunter** is a defensive toolkit for inventorying and reviewing IoT devices on networks you own or are authorized to assess. The current development branch identifies itself as **v3.1**.

## Capabilities

- Local-network device discovery
- Service and banner fingerprinting
- Vendor identification using available OUI data
- CVE information lookup based on detected service details
- Protocol configuration review
- Network-traffic anomaly monitoring
- Remediation guidance
- PDF and JSON report generation with inventory change summaries
- Local device inventory snapshots with new, missing, and changed-device tracking
- Private IPv4 range limits for the desktop scanner
- Explicit authorization confirmation in the desktop scanner
- Tkinter graphical interface

Some checks depend on operating-system permissions, network visibility, optional system packages, and external vulnerability-data services. Findings are leads for review, not proof of exploitability.

## Requirements

- Python 3.10+
- Dependencies in [requirements.txt](requirements.txt)
- Optional platform support packages as described below

## Installation

Clone the repository and install its Python dependencies:

```bash
git clone https://github.com/mrcyberharsh/iot-hunter.git
cd iot-hunter
python -m pip install --upgrade pip\npython -m pip install -r requirements.txt\npython -m unittest discover -s tests -v
```

### Linux

Install the system packages required by your selected network interfaces and packet-capture features:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev libpcap-dev
```

### Windows

1. Install Python 3.10 or newer.
2. Install Npcap if required by the packet-capture functionality.
3. Open PowerShell and install the Python dependencies.

### macOS

Install Python and the required packet-capture support through trusted package sources, then install the Python dependencies.

## Launch

CLI:

```bash
python iothunter.py
```

GUI:

```bash
python gui.py
```

The full scan records local inventory snapshots at `data/inventory-history.json`. The file is local-only and excluded from Git. The default full-scan workflow does not perform credential guessing; use your approved device-management process for credential audits.

## Repository layout

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

## Inventory history\n\nEach full scan stores a compact snapshot containing IP address, MAC address, vendor, hostname, device type, and observed open ports. The next run compares the current inventory with the previous snapshot and reports newly observed, missing, and changed devices. History is capped at 50 snapshots. Review the local history file carefully before sharing it because it contains internal network metadata.\n\n## Understanding results

- Service banners and version strings can be inaccurate or intentionally obscured.
- CVE search results may include false positives; verify product, version, configuration, and vendor advisories.
- Anomaly alerts are indicators that need context from a network administrator.
- Reports should be reviewed before sharing because they may contain internal host and service details.

## Authorization and safe operation

Use IoT Hunter only on devices and private networks you own or have explicit written permission to assess. The desktop scanner asks for authorization confirmation and limits manually entered ranges to private IPv4 networks up to /24. Keep testing within the agreed scope and use conservative settings. The default full-scan workflow skips credential guessing. Do not attempt to access accounts, disrupt devices, or test third-party networks without authorization.

## Contributing

Issues and pull requests are welcome. Include your OS, Python version, relevant module, expected behavior, and sanitized logs. Never publish credentials, private IP inventories, packet captures, or other sensitive network data in public issues.

## Author and license

Created by **Harsh Saini · MR CYBER PULSE**.

- GitHub: https://github.com/mrcyberharsh
- Project: https://github.com/mrcyberharsh/iot-hunter

Licensed under **GNU GPL-3.0**. See [LICENSE](LICENSE).
