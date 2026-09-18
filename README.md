# 🛡️ MR IOT HUNTER — All-in-One IoT Security Toolkit

> *"Complex ko simple. Simple ko powerful."*

**Built by MR CYBER (Harsh Saini)** — cybersecurity builder, OSINT specialist, hardware + software combo.

![Version](https://img.shields.io/badge/version-1.0-brightgreen)
![License](https://img.shields.io/badge/license-GPL--3.0-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-lightgrey)

---

## 📌 Overview

**MR IOT HUNTER** is a lightweight but powerful IoT security auditing toolkit built for **network discovery, credential testing, firmware analysis, protocol inspection, and anomaly detection**.

It is designed for **defensive security researchers, ethical hackers, and IT admins** who want to identify misconfigurations, weak/default credentials, and insecure protocols in their own lab or enterprise environments.

> 🔒 **Passwords are NEVER stored in plaintext.** All credentials are hashed using **Keccak‑512** (SHA‑3 family) before logging or reporting.

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| **Discovery & Inventory** | Ping sweep + port scan (22, 23, 21, 80, 443, 554, 1883, 8080, etc.) with MAC vendor lookup |
| **Credential Scanner** | Tests default credentials over Telnet, SSH, and HTTP Basic Auth using a curated top‑50 IoT password list |
| **Firmware Analysis** | Extracts firmware/version info when exposed and cross‑checks against the NVD CVE database |
| **Network Anomaly Monitor** | Sniffs for DNS beaconing to suspicious TLDs (`.ru`, `.cn`, `.top`, `.xyz`) and unusual outbound ports |
| **Protocol Analysis** | Detects plaintext credentials in Telnet, FTP, HTTP, and MQTT traffic |
| **Remediation Engine** | Generates actionable mitigation steps (iptables rules, VLAN isolation, firmware update advice) |
| **Full Report** | Exports structured JSON reports with hashed credentials and a vulnerability summary |

---

## 🔑 Security — Keccak‑512 Hashing

All discovered credentials are **hashed using Keccak‑512** (SHA‑3 family).

- ✅ Passwords are **never printed or stored in plaintext**
- ✅ Weak / default passwords trigger **CRITICAL / WEAK** alerts
- ✅ Hashes are one‑way — they cannot be reversed, but they can be verified against known hashes

**Example**

```
Password    : admin123
Keccak-512  : 0x4a53c9c6e7c9a6c...
Status      : ⚠ WEAK — matches known default
```

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/mrcyberharsh/iot-hunter.git
cd iot-hunter
```

### 2. Install dependencies

Dependencies are auto‑installed on first run, but you can install them manually:

```bash
pip install requests paramiko scapy
```

### 3. Make it executable & run

```bash
chmod +x iot_hunter.py
sudo python3 iot_hunter.py
```

> **Note:** Root privileges are required for packet sniffing (`scapy`).

---

## 🧪 Usage

### Full interactive menu

```bash
sudo python3 iot_hunter.py
```

### Quick password strength check (standalone)

```bash
python3 iot_hunter.py --check-pwd "myPassword123"
```

### Scan a specific target

Inside the menu:

1. Select `[2] Credential Scanner`
2. Enter target IP (e.g. `192.168.1.45`)
3. The tool tests default credentials and displays **only their Keccak‑512 hashes** with a strength status

---

## 📁 Output Structure

All reports are saved inside the `reports/` directory:

```
reports/
├── discovery_20260307_123456.json
├── credscan_20260307_123456.txt      # hashed passwords only
└── full_report_20260307_123456.json
```

---

## 🛡️ Disclaimer

**MR IOT HUNTER is intended SOLELY for educational and defensive security purposes.**

- ✅ Use it **only on networks and devices you own** or have explicit written permission to test.
- ❌ Unauthorized scanning or credential testing is **ILLEGAL** and violates laws such as the **IT Act 2000** (India) and the **CFAA** (USA).
- 🧑‍⚖️ The author (**Harsh Saini**) is **not responsible** for any misuse of this tool.

> *"With great power comes great responsibility."* — Use it ethically.

---

## 💼 Commercial Licensing & Partnerships

This project is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

If you are an **enterprise, firmware developer, or hardware manufacturer (EMS)** looking to integrate **MR IOT HUNTER** code, modules, or features into a proprietary, closed‑source product, **you cannot use this public version for free.**

Dual‑licensing commercial frameworks, optimized hardware firmware ports, and custom UI dashboards are available. For corporate acquisition, hardware joint ventures, or vendor integration inquiries, please contact management directly.

---

## 🤝 Contributing

Pull requests, bug reports, and feature suggestions are welcome!

Please ensure your contributions align with the **defensive & educational** nature of this project.

---

## 📬 Contact

**Harsh Saini (MR CYBER)**

- **Manager:** [manager.prachi@zohomail.in](mailto:manager.prachi@zohomail.in)
- **CC:** [cyber.h4rsh@zohomail.in](mailto:cyber.h4rsh@zohomail.in)
- **GitHub:** [@mrcyberharsh](https://github.com/mrcyberharsh)

---

## ⭐ Star the Project

If you find this tool useful, please **⭐ star the repo** — it helps others discover it and motivates me to keep building. 🚀

---

**Made with ☕ and 🔐 in India.**
