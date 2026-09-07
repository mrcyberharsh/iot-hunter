# 🛡️ IOT HUNTER — All-in-One IoT Security Toolkit

> *"Complex ko simple. Simple ko powerful."*

Built by **MR CYBER** (Harsh Saini) — cybersecurity builder, OSINT specialist, hardware+software combo.

---![Version](https://img.shields.io/badge/version-1.0-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.6%2B-blue)
![Build](https://img.shields.io/badge/build-passing-brightgreen)

## 📌 Overview

**MR LOT HUNTER** is a lightweight but powerful IoT security auditing tool built for **network discovery, credential testing, firmware analysis, and anomaly detection**.  

It is designed for **defensive security researchers, ethical hackers, and IT admins** who want to identify misconfigurations, weak/default credentials, and insecure protocols in their own lab or enterprise environments.

🔒 **Passwords are NEVER stored in plaintext** – all credentials are hashed using **Keccak-512** (SHA-3 family) before logging or reporting.

---

## 🚀 Features

| Module | Description |
|--------|-------------|
| **Discovery & Inventory** | Ping sweep + port scan (23, 22, 80, 443, 554, 8080, 1883, 21, etc.) with MAC vendor lookup |
| **Credential Scanner** | Tests default credentials over Telnet, SSH, HTTP Basic Auth (top 50 IoT passwords) |
| **Firmware Analysis** | Extracts version info (if available) and queries NVD CVE database for known vulnerabilities |
| **Network Anomaly Monitor** | Sniffs for DNS beaconing to suspicious TLDs (.ru, .cn, .top, .xyz) and unusual outbound ports |
| **Protocol Analysis** | Detects plaintext credentials in Telnet, FTP, HTTP, and MQTT traffic |
| **Remediation Engine** | Generates actionable mitigation steps (iptables rules, VLAN isolation, firmware update advice) |
| **Full Report** | Exports structured JSON reports with hashed credentials and vulnerability summary |

---

## 🔑 Security – Keccak-512 Hashing

All discovered credentials are **hashed using Keccak-512** (part of the SHA-3 family).  
- ✅ Passwords are **never printed or stored in plaintext**  
- ✅ Weak/default passwords trigger **CRITICAL / WEAK** alerts  
- ✅ Hashes are one-way – you cannot reverse them, but you can verify against known hashes

**Example hash:**
```
Password: admin123
Keccak-512: 0x4a53c9c6e7c9a6c...
```

---

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/mr-lot-hunter.git
cd mr-lot-hunter
```

### 2. Install dependencies (auto-installed on first run, but manual install if needed)
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

## 🧪 Usage Examples

### Full interactive menu
```bash
sudo python3 iot_hunter.py
```

### Quick password strength check (standalone)
```bash
python3 iot_hunter.py --check-pwd "myPassword123"
```

### Scan a specific target (inside menu)
1. Select `[2] Credential Scanner`  
2. Enter target IP (e.g., `192.168.1.45`)  
3. Tool will test default credentials and display only their Keccak-512 hashes with strength status

---

## 📁 Output Structure

All reports are saved inside the `reports/` directory:

```
reports/
├── discovery_20260307_123456.json
├── credscan_20260307_123456.txt   # hashed passwords only
└── full_report_20260307_123456.json
```

---

## 🛡️ Disclaimer

**MR LOT HUNTER is intended SOLELY for educational and defensive security purposes.**  

- ✅ Use it **only on networks and devices you own** or have explicit written permission to test.  
- ❌ Unauthorized scanning or credential testing is **ILLEGAL** and violates laws like the IT Act 2000 (India) and CFAA (USA).  
- 🧑‍⚖️ The author (Harsh Saini) is **not responsible** for any misuse of this tool.  

> *"With great power comes great responsibility."* – Use it ethically.

---

## 🤝 Contributing

Pull requests, bug reports, and feature suggestions are welcome!  
Please ensure your contributions align with the **defensive & educational** nature of this project.

---

## 📬 Contact

**Harsh Saini (MR CYBER)**  
- GitHub: [@yourusername](https://github.com/yourusername)  
- Book: *"The Unseen Human Firewall"* (Coming Soon)

---

## ⭐ Star the Project

If you find this tool useful, please **⭐ star the repo** – it helps others discover it and motivates me to keep building. 🚀

---

**Made with ☕ and 🔐 in India.**
