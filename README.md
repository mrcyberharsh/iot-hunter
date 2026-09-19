# IoT Hunter v2.0
Built by **MR CYBER (Harsh Saini)**
*"Complex ko Simple. Simple ko Powerful."*
GitHub: github.com/mrcyberharsh/iot-hunter

Defensive IoT security toolkit: discovery, fingerprinting, default-credential
checks, live anomaly detection, insecure-protocol detection, remediation
planning, and local PDF/JSON reporting. **Real network capture only — no demo
data, no external APIs.**

## ⚠️ Legal Disclaimer
Only scan networks and devices you own or are explicitly authorized to test.
Unauthorized scanning of networks is illegal in most jurisdictions. The tool
requires explicit confirmation of authorization before every run.

## Requirements
```
pip install -r requirements.txt
```

### Platform-specific setup
- **Linux**: `libpcap` usually preinstalled; may need `sudo apt install libpcap-dev`. Run with `sudo` for raw sockets/ARP.
- **Windows**: Install **Npcap** (https://npcap.com) with "WinPcap API-compatible mode" enabled. Run terminal as Administrator.
- **macOS**: Install libpcap via `brew install libpcap`. Run with `sudo`.

## Configuration
Edit `config.yaml`:
- `interface` / `subnet`: leave as `auto` for auto-detection
- `wordlist_path`: path to your local `user:pass` wordlist (a starter list is in `modules/data/default_creds.txt`)
- `thresholds`: tune anomaly detection sensitivity
- `report_path`: where PDF/JSON reports are saved

## Usage
```
python iothunter.py
```
You'll see the banner, then a disclaimer prompt requiring `YES` to proceed,
then a menu:
1. Full scan (discovery → fingerprint → credentials → protocol → anomaly → report)
2. Discovery only
3. Protocol scan only (30s live capture)
4. Anomaly monitor only
5. Exit

Reports are saved locally under `reports/` as timestamped PDF (watermarked)
and JSON files. Logs are written to `logs/iothunter.log`.

## Module Overview
| Module | Purpose |
|---|---|
| `discovery.py` | ARP scan (scapy) + port scan + OUI vendor lookup |
| `fingerprint.py` | Banner grabbing + device-type classification |
| `credentials.py` | Local wordlist default-credential testing, rate-limited |
| `anomaly.py` | Live packet capture, rolling-window stats for beaconing/scan/exfil |
| `protocol.py` | Detects Telnet/FTP/HTTP/unencrypted MQTT + plaintext creds |
| `remediation.py` | Maps findings to prioritized fixes and commands |
| `reporting.py` | Generates watermarked PDF + JSON reports locally |

## Notes
- ARP scanning and packet capture require elevated privileges (root/Administrator).
- No hardcoded IPs, no simulated data — all findings come from real traffic/scans on your own network.
