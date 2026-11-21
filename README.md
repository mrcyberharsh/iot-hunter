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

- **Local-network Discovery:** Active scanning and device inventorying.
- **Fingerprinting:** Service, banner, and vendor identification (OUI lookup).
- **Vulnerability Lookup:** CVE information based on detected services.
- **TLS / Certificate Hygiene:** Expiry, weak ciphers, and self-signed certificate detection.
- **Protocol Review:** Configuration checking for IoT protocols.
- **Reporting:** PDF and JSON generation with inventory change summaries.
- **History Tracking:** Local snapshots with new, missing, and changed-device tracking.
- **Safe by Default:** Private IPv4 range limits, explicit authorization confirmation, and no default credential guessing.

## Requirements

- **Python** 3.10+
- Dependencies in [`requirements.txt`](requirements.txt)
- Optional platform support packages (Npcap for Windows, libpcap for Linux/macOS)

## Installation

Clone the repository and create a Python environment. Run the commands below from a terminal on your system.

```bash
git clone https://github.com/mrcyberharsh/iot-hunter.git
cd iot-hunter
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

If `python` is not available on Linux or macOS, use `python3` for the commands above.

### 🐧 Linux

1. Install Python 3.10+, Tkinter, pip, and libpcap development tools.

   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-dev python3-tk libpcap-dev
   ```

   For distributions that do not use `apt`, install equivalent packages with your package manager.

2. Clone the repository and install the dependencies:

   ```bash
   git clone https://github.com/mrcyberharsh/iot-hunter.git
   cd iot-hunter
   python3 -m pip install --upgrade pip
   python3 -m pip install -r requirements.txt
   python3 -m unittest discover -s tests -v
   ```

3. Packet capture may require elevated privileges. Run discovery or a protocol scan from a terminal with the required network permissions:

   ```bash
   sudo python3 iothunter.py
   ```

   Type `YES` at the authorization prompt, then choose `2` (Discovery only) for a first test.

### 🪟 Windows

IoT Hunter uses [Scapy](https://scapy.net/) for ARP discovery and live packet capture. On Windows this requires **Npcap**, so install it before running a scan.

1. **Install Python 3.10 or newer** from [python.org](https://www.python.org/downloads/windows/). Tick **"Add python.exe to PATH"** in the installer.
2. **Install Npcap** (packet-capture library):
   - Download the installer only from the official site: <https://npcap.com/#download>.
   - Run the installer and keep **"Install Npcap in WinPcap API-compatible Mode"** checked.
   - Restart the terminal (or reboot) after installation.
3. **Open PowerShell as Administrator.** Right-click *Windows PowerShell* (or *Terminal*) in the Start menu and choose **Run as administrator**.
   > ⚠️ Administrator rights are required for network scans. Without them, ARP discovery and packet capture fail or return no results.
4. **Clone the repository and install the Python dependencies:**
   ```powershell
   git clone https://github.com/mrcyberharsh/iot-hunter.git
   cd iot-hunter
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   python -m unittest discover -s tests -v
   ```
5. **Run a scan** from the same Administrator terminal:
   ```powershell
   python iothunter.py
   ```
   Type `YES` at the authorization prompt, then choose `2` (Discovery only) for a first test.

Example of a successful discovery on Windows (illustrative, with sanitized placeholder values; your interface name, addresses, and devices will differ):

```text
DISCLAIMER: Only scan networks and devices you own or are
explicitly authorized to test. Unauthorized scanning may be illegal.
Type YES to confirm you are authorized to scan this network: YES

Select an option:
  1) Full scan (discovery + fingerprint + inventory history + protocol + anomaly + report)
  2) Discovery only
  3) Protocol scan only
  4) Anomaly monitor only
  5) Exit

Choice: 2
[*] Interface: Wi-Fi  IP: 192.0.2.10  Subnet: 192.0.2.0/24
[*] Running ARP discovery on the active local subnet...
```

**Troubleshooting**

- `No libpcap provider available` or `winpcap is not installed`: Npcap is missing or was installed without WinPcap API-compatible mode. Reinstall it from <https://npcap.com/>.
- Scan finishes with no devices: confirm the terminal is running as Administrator and that you are connected to the network you intend to assess.
- `python` is not recognized: reinstall Python with **Add python.exe to PATH** ticked, or use `py -m pip ...` and `py iothunter.py`.

### 🍎 macOS

1. Install Python 3.10 or newer and Homebrew's libpcap tools:

   ```bash
   brew install python libpcap
   ```

   If Homebrew is not installed, use <https://brew.sh/> or your preferred trusted package manager.

2. Clone the repository and install the dependencies:

   ```bash
   git clone https://github.com/mrcyberharsh/iot-hunter.git
   cd iot-hunter
   python3 -m pip install --upgrade pip
   python3 -m pip install -r requirements.txt
   python3 -m unittest discover -s tests -v
   ```

3. Run the tool from the terminal:

   ```bash
   sudo python3 iothunter.py
   ```

   Type `YES` at the authorization prompt, then choose `2` (Discovery only) for a first test. Packet-capture permissions may require an Administrator account or macOS network-security approval.

## Launch

**CLI Mode:**

```bash
python iothunter.py
```

**GUI Mode:**

```bash
python gui.py
```

On systems where `python` is unavailable, use `python3 iothunter.py` or `python3 gui.py`.

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

## Inventory History

Each full scan stores a compact snapshot containing IP address, MAC address, vendor, hostname, device type, and observed open ports. The next run compares the current inventory with the previous snapshot and reports newly observed, missing, and changed devices.

- History is capped at **50 snapshots**.
- Review the local history file carefully before sharing it because it contains internal network metadata.

## Understanding Results

- **Service banners** and version strings can be inaccurate or intentionally obscured.
- **CVE search results** may include false positives; verify product, version, and vendor advisories.
- **Anomaly alerts** are indicators that need context from a network administrator.
- **Reports** should be reviewed before sharing because they may contain internal host and service details.

## Authorization & Safe Operation

Use IoT Hunter **only** on devices and private networks you own or have explicit written permission to assess.

- The desktop scanner asks for authorization confirmation.
- Manually entered ranges are limited to private IPv4 networks up to `/24`.
- The default workflow skips credential guessing.
- **Do not** attempt to access accounts, disrupt devices, or test third-party networks without authorization.

## 🤝 Contributing

Issues and pull requests are welcome!
Please check out our **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** before submitting.
Never publish credentials, private IP inventories, packet captures, or other sensitive network data in public issues.

## Author & License

Created by **Harsh Saini · MR Cyber Pulse**.

- **GitHub:** [@mrcyberharsh](https://github.com/mrcyberharsh)
- **Project:** [iot-hunter](https://github.com/mrcyberharsh/iot-hunter)
- **Contact:** cyber.h4rsh@zohomail.in

Licensed under **GNU GPL-3.0**. See [`LICENSE`](LICENSE) for details.

## 🌱 Contributors Welcome

IoT Hunter is actively looking for contributors! Whether you're fixing a typo or building a new audit module — your help matters.

**Good first issues:** [Browse beginner-friendly tasks →](https://github.com/mrcyberharsh/iot-hunter/labels/good%20first%20issue)

**Not sure where to start?** Open an issue and say hi — we'll help you find something.

