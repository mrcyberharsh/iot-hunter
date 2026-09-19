cat > README.md << 'EOF'
# IoT Hunter v2.0

Built by MR CYBER (Harsh Saini)
"Complex ko Simple. Simple ko Powerful."

GitHub: https://github.com/mrcyberharsh/iot-hunter

Defensive IoT security toolkit: discovery, fingerprinting, default-credential checks, live anomaly detection, insecure-protocol detection, remediation planning, and local PDF/JSON reporting. Real network capture only — no demo data, no external APIs.

---

## Legal Disclaimer

Only scan networks and devices you own or are explicitly authorized to test.
Unauthorized scanning of networks is illegal in most jurisdictions. This tool requires explicit confirmation of authorization before every run.

---

## Requirements

pip install -r requirements.txt

### Platform-Specific Setup

- Linux: libpcap usually preinstalled; may need sudo apt install libpcap-dev. Run with sudo for raw sockets/ARP.
- Windows: Install Npcap (https://npcap.com) with "WinPcap API-compatible mode" enabled. Run terminal as Administrator.
- macOS: Install libpcap via brew install libpcap. Run with sudo.

---

## Configuration

Edit config.yaml:

- interface / subnet: leave as auto for auto-detection
- wordlist_path: path to your local user:pass wordlist (starter list is in modules/data/default_creds.txt)
- thresholds: tune anomaly detection sensitivity
- report_path: where PDF/JSON reports are saved

---

## Usage

python iothunter.py

You'll see the banner, then a disclaimer prompt requiring YES to proceed, then a menu:

1. Full Scan — discovery -> fingerprint -> credentials -> protocol -> anomaly -> report
2. Discovery Only — ARP scan + port scan + OUI vendor lookup
3. Protocol Scan Only — 30s live capture for insecure protocols
4. Anomaly Monitor Only — real-time traffic monitoring
5. Exit

Reports are saved locally under reports/ as timestamped PDF (watermarked) and JSON files. Logs are written to logs/iothunter.log.

---

## Module Overview

- discovery.py: ARP scan (scapy) + port scan + OUI vendor lookup
- fingerprint.py: Banner grabbing + device-type classification
- credentials.py: Local wordlist default-credential testing, rate-limited
- anomaly.py: Live packet capture, rolling-window stats for beaconing/scan/exfil
- protocol.py: Detects Telnet/FTP/HTTP/unencrypted MQTT + plaintext creds
- remediation.py: Maps findings to prioritized fixes and commands
- reporting.py: Generates watermarked PDF + JSON reports locally

---

## Notes

- ARP scanning and packet capture require elevated privileges (root/Administrator).
- No hardcoded IPs, no simulated data — all findings come from real traffic/scans on your own network.
- Tested on Linux (Parrot OS, Kali), Windows 10/11, and macOS (Intel & Apple Silicon).

---

## Author & Credits

Harsh Saini (MR CYBER)
17-year-old GRC & Defensive Cybersecurity Learner
"Builders don't stop. They rebuild."

- Website: https://mrcyberharsh.github.io
- GitHub: https://github.com/mrcyberharsh
- LinkedIn: https://linkedin.com/in/mrcyberharsh
- Business Email: manager.prachi@zohomail.in
- Manager: prachi sharma 

---

## Support & Contribution

If you find this tool useful, please consider:

- Starring the repo on GitHub
- Reporting bugs via GitHub Issues
- Contributing via Pull Requests
- Sharing with the security community

---

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0).
See the LICENSE file for details.

---

Built with love by MR CYBER
Complex ko Simple. Simple ko Powerful.
EOF
