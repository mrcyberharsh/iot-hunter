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

**IoT Hunter** is a defensive toolkit for inventorying and reviewing IoT devices on networks you own or are authorized to assess. The source currently identifies itself as **v3.0**; this README intentionally avoids the older v2.1 label.

## Capabilities

- Local-network device discovery
- Service and banner fingerprinting
- Vendor identification using available OUI data
- CVE information lookup based on detected service details
- Protocol configuration review
- Network-traffic anomaly monitoring
- Remediation guidance
- PDF and JSON report generation
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
python -m pip install -r requirements.txt
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

Use the built-in help/menu and the repository configuration to understand the available modes for your version.

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

## Understanding results

- Service banners and version strings can be inaccurate or intentionally obscured.
- CVE search results may include false positives; verify product, version, configuration, and vendor advisories.
- Anomaly alerts are indicators that need context from a network administrator.
- Reports should be reviewed before sharing because they may contain internal host and service details.

## Authorization and safe operation

Use IoT Hunter only on devices and networks you own or have explicit written permission to assess. Keep testing within the agreed scope and use conservative settings. Do not attempt to access accounts, disrupt devices, or test third-party networks without authorization.

## Contributing

Issues and pull requests are welcome. Include your OS, Python version, relevant module, expected behavior, and sanitized logs. Never publish credentials, private IP inventories, packet captures, or other sensitive network data in public issues.

## Author and license

Created by **Harsh Saini · MR CYBER PULSE**.

- GitHub: https://github.com/mrcyberharsh
- Project: https://github.com/mrcyberharsh/iot-hunter

Licensed under **GNU GPL-3.0**. See [LICENSE](LICENSE).
