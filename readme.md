<div align="center">

<img src="logo.png" alt="MR CYBER PULSE" width="380" />

<br />

# 🛡️ IoT Hunter

**Next-Gen Defensive IoT Security & Network Reconnaissance Toolkit**

[![Version](https://img.shields.io/badge/Version-v3.1%20%7C%20v4.0--Preview-00E5FF?style=flat-square&logo=semver&logoColor=white)](https://github.com/mrcyberharsh/iot-hunter)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPLv3-2EA043?style=flat-square&logo=gnu&logoColor=white)](LICENSE)
[![Stars](https://img.shields.io/github/stars/mrcyberharsh/iot-hunter?style=flat-square&logo=github&color=F59E0B)](https://github.com/mrcyberharsh/iot-hunter/stargazers)
[![Issues](https://img.shields.io/github/issues/mrcyberharsh/iot-hunter?style=flat-square&logo=github&color=EF4444)](https://github.com/mrcyberharsh/iot-hunter/issues)
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-8B5CF6?style=flat-square&logo=git&logoColor=white)](https://github.com/mrcyberharsh/iot-hunter/pulls)

[Features](#-core-capabilities) • [Quick Start](#-quick-start) • [v4 Web Dashboard](#-v40-web-dashboard-preview) • [Architecture](#-architecture) • [Safety](#-safety--authorization)

</div>

---

> **⚠️ Security Notice:** IoT Hunter is strictly a **defensive auditing tool** for networks you own or have explicit written authorization to assess. Findings represent *leads for review*, not proof of exploitability.

## ⚡ Core Capabilities

| Module | Capability | Description |
| :--- | :--- | :--- |
| 🔍 **Discovery** | Active ARP & Subnet Scan | Rapidly inventories live hosts on private IPv4 segments (`/24` max). |
| 🧬 **Fingerprinting** | Service, Banner & OUI | Identifies hardware vendors via MAC OUI and extracts service banners. |
| 🛡️ **Vuln Lookup** | CVE Intelligence | Maps detected services and versions against known CVE advisories. |
| 🔐 **TLS Hygiene** | Certificate & Cipher Audit | Flags expired, self-signed, or weak-cipher TLS endpoints. |
| 📡 **Protocol Audit** | IoT Traffic Inspection | Reviews configurations across common IoT communication protocols. |
| 📈 **Drift Tracking** | Snapshot History | Tracks new, missing, and modified devices across the last 50 scans. |
| 📄 **Reporting** | Automated Exports | Generates clean PDF and JSON audit reports with remediation guidance. |

---

## 🚀 Quick Start

### 1. Clone & Setup

```bash
git clone https://github.com/mrcyberharsh/iot-hunter.git
cd iot-hunter
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

### 2. Platform Prerequisites

<details>
<summary><b>🐧 Linux (Debian / Ubuntu)</b></summary>
<br>

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-dev python3-tk libpcap-dev
sudo python3 iothunter.py
```
</details>

<details>
<summary><b>🪟 Windows (Requires Npcap + Admin)</b></summary>
<br>

1. Install **Python 3.10+** (check *"Add python.exe to PATH"*).
2. Install **[Npcap](https://npcap.com/#download)** with **"WinPcap API-compatible Mode"** enabled.
3. Open **PowerShell as Administrator** and run:
```powershell
python iothunter.py
```
</details>

<details>
<summary><b>🍎 macOS (Homebrew)</b></summary>
<br>

```bash
brew install python libpcap
sudo python3 iothunter.py
```
</details>

### 3. Launch Modes

```bash
# Interactive CLI Scanner
sudo python3 iothunter.py

# Desktop GUI (Tkinter)
sudo python3 gui.py
```

<details>
<summary><b>📟 View Sample CLI Output</b></summary>
<br>

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
</details>

---

## 🌐 v4.0 Web Dashboard (Preview)

The `feature/iot-hunter-v4` branch wraps the v3.1 scanning engine in a modern **FastAPI dark-mode web dashboard** while keeping CLI and Tkinter modes intact.

### 🐳 Docker Deployment

```bash
cp .env.example .env
# Set a strong random value for IOT_HUNTER_ADMIN_SECRET in .env
docker compose up --build
```
Access the dashboard at **`http://localhost:8080`** *(OpenAPI docs at `/docs`)*.

### 🔌 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Dark-mode single-page web dashboard |
| `POST` | `/api/auth/token` | Issue Bearer token via `X-Admin-Secret` header |
| `POST` | `/api/scan` | Trigger an explicitly authorized subnet scan |
| `GET` | `/api/scan/{id}/status` | Poll active scan progress and state |
| `GET` | `/api/devices` | Retrieve discovered device inventory |
| `POST` | `/api/schedule` | Configure cron-based recurring scans |
| `GET` | `/api/report/{id}/pdf` | Download generated PDF audit report |

> **⚠️ v4 Preview Caveats:** Scheduled jobs are currently process-local (Redis is provisioned for upcoming queue integration). Do not expose port `8080` directly to the public internet without a TLS reverse proxy and hardened access controls.

---

## 📂 Architecture

```text
iot-hunter/
├── iothunter.py          # Core CLI entry point
├── gui.py                # Tkinter desktop interface
├── config.yaml           # Scanner configuration & thresholds
├── modules/
│   ├── discovery.py      # ARP & host discovery
│   ├── fingerprint.py    # Banner grabbing, OUI & CVE mapping
│   ├── protocol.py       # IoT protocol checks
│   ├── anomaly.py        # Traffic & baseline anomaly detection
│   ├── credentials.py    # Safe configuration & hygiene checks
│   ├── remediation.py    # Actionable hardening guidance
│   └── reporting.py      # PDF & JSON report builder
├── data/                 # Local SQLite & inventory snapshots (gitignored)
├── reports/              # Generated audit reports
└── logs/                 # Execution logs
```

---

## 🛡️ Safety & Authorization

IoT Hunter is engineered with strict defensive guardrails:
- **Explicit Consent Gate:** Requires manual `YES` confirmation (or API authorization flag) before transmitting packets.
- **Scope Enforcement:** Strictly restricted to private IPv4 ranges (up to `/24` per subnet).
- **Zero Bruteforce:** No default credential guessing or intrusive exploitation is performed.
- **Local Privacy:** Inventory history (`data/inventory-history.json`, capped at 50 snapshots) stays strictly local. Review reports before sharing externally.

---

## 🤝 Contributing & License

Contributions, bug reports, and feature ideas are welcome! Check **[CONTRIBUTING.md](CONTRIBUTING.md)** and **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** before opening a PR. *(Never include real internal IPs, PCAPs, or credentials in public issues.)*

- **Browse beginner tasks:** [`good first issue`](https://github.com/mrcyberharsh/iot-hunter/labels/good%20first%20issue)
- **Author:** Harsh Saini · [MR Cyber Pulse](https://github.com/mrcyberharsh) (`cyber.h4rsh@zohomail.in`)
- **License:** Distributed under the **GNU GPL-3.0** License. See [`LICENSE`](LICENSE) for details.