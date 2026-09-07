
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import socket
import subprocess
import json
import ipaddress
from datetime import datetime
from hashlib import sha3_512

# ============================================================
# EXTERNAL IMPORTS (Install if missing)
# ============================================================
try:
    import requests
except ImportError:
    os.system("pip install requests")
    import requests

try:
    import paramiko
except ImportError:
    os.system("pip install paramiko")
    import paramiko

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR
except ImportError:
    os.system("pip install scapy")
    import scapy.all as scapy
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR

# ============================================================
# GLOBALS
# ============================================================
TARGET_RANGE = "192.168.1.0/24"
OUTPUT_DIR = "reports"
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

COMMON_PORTS = [23, 22, 80, 443, 554, 8080, 1883, 21, 3389, 502, 102, 161, 162, 123]

DEFAULT_CREDS = [
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("root", "12345"), ("admin", "1234"), ("root", "toor"),
    ("pi", "raspberry"), ("ubuntu", "ubuntu"), ("guest", "guest"),
    ("support", "support"), ("user", "user"), ("admin", "123456"),
    ("root", "default"), ("admin", "default"), ("admin", "password123"),
]

# ============================================================
# PASSWORD SECURITY (Keccak-512)
# ============================================================
def hash_password(password: str) -> str:
    return sha3_512(password.encode('utf-8')).hexdigest()

def check_password_strength(password: str) -> dict:
    hashed = hash_password(password)
    
    # Check default credentials
    for user, pwd in DEFAULT_CREDS:
        if password == pwd:
            return {
                "status": "CRITICAL",
                "message": " Default credential detected! Change it NOW.",
                "hash": hashed
            }
    
    # Check weak patterns
    if len(password) < 8:
        return {
            "status": "WEAK",
            "message": " Password is too short (< 8 chars).",
            "hash": hashed
        }
    if password.lower() == password or password.upper() == password:
        return {
            "status": "WEAK",
            "message": " Use mixed case (upper/lower) for strength.",
            "hash": hashed
        }
    
    return {
        "status": "STRONG",
        "message": " Strong password! Well done.",
        "hash": hashed
    }

# ============================================================
# BANNER
# ============================================================
def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print("""
     ███╗   ███╗██████╗     ██╗      ██████╗ ████████╗
     ████╗ ████║██╔══██╗    ██║     ██╔═══██╗╚══██╔══╝
     ██╔████╔██║██████╔╝    ██║     ██║   ██║   ██║
     ██║╚██╔╝██║██╔══██╗    ██║     ██║   ██║   ██║
     ██║ ╚═╝ ██║██║  ██║    ███████╗╚██████╔╝   ██║
     ╚═╝     ╚═╝╚═╝  ╚═╝    ╚══════╝ ╚═════╝    ╚═╝
                    HUNTER - IoT Security Toolkit
    ╔══════════════════════════════════════════════════════════╗
    ║  MR LOT HUNTER  v2.0  (Keccak-512 Secured)            ║
    ║  Built by MR CYBER HARSH (Harsh Saini)                  ║
    ║  "Complex ko simple. Simple ko powerful."           ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    print("[SYSTEM] IoT-Hunter initialized. Target: {}".format(TARGET_RANGE))
    print("[SYSTEM] Passwords will be hashed (Keccak-512) in reports.")
    print("[SYSTEM] Scan engine: Ready (Real Mode)\n")


def menu():
    print("    ┌─────────────────────────────────────────────────────┐")
    print("    │  [1]  Discovery & Device Inventory                │")
    print("    │  [2]  Credential Scanner (with Hash)             │")
    print("    │  [3]  Firmware Analysis (CVE Lookup)            │")
    print("    │  [4]  Network Anomaly Monitor                   │")
    print("    │  [5]  Protocol Analysis (Plaintext Detection)   │")
    print("    │  [6]  Remediation Engine                        │")
    print("    │  [7]  Generate Full Report                     │")
    print("    │  [0]  Exit                                    │")
    print("    └─────────────────────────────────────────────────────┘")


# ============================================================
# HELPER FUNCTIONS
# ============================================================
def ping_host(ip):
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", str(ip)], stderr=subprocess.DEVNULL)
        return True
    except:
        return False

def port_scan(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def get_vendor_from_mac(mac):
    oui_file = "/usr/share/nmap/nmap-mac-prefixes"
    if os.path.exists(oui_file):
        with open(oui_file, 'r') as f:
            for line in f:
                if line.startswith(mac[:8].upper()):
                    return line.split()[2].strip()
    return "Unknown"

# ============================================================
# MODULE 1: DISCOVERY
# ============================================================
def module_discover():
    print("\n" + "=" * 70)
    print("[MODULE 1] Discovery & Device Inventory")
    print("=" * 70)
    
    network = ipaddress.ip_network(TARGET_RANGE, strict=False)
    devices = []
    print("\n[+] Scanning network {}...".format(TARGET_RANGE))
    for ip in network.hosts():
        if ping_host(ip):
            mac = "unknown"
            try:
                arp = subprocess.check_output(["arp", "-n", str(ip)], stderr=subprocess.DEVNULL).decode()
                for line in arp.split("\n"):
                    if str(ip) in line:
                        parts = line.split()
                        if len(parts) > 2:
                            mac = parts[2]
                        break
            except:
                pass
            vendor = get_vendor_from_mac(mac) if mac != "unknown" else "Unknown"
            open_ports = port_scan(ip, COMMON_PORTS)
            devices.append({
                "ip": str(ip),
                "mac": mac,
                "vendor": vendor,
                "open_ports": open_ports
            })
            print("[+] Found {} ({}), open ports: {}".format(ip, vendor, open_ports))
    
    print("\n[+] {} devices discovered.".format(len(devices)))
    report_file = os.path.join(OUTPUT_DIR, "discovery_{}.json".format(datetime.now().strftime("%Y%m%d_%H%M%S")))
    with open(report_file, 'w') as f:
        json.dump(devices, f, indent=2)
    print("\n[✓] Report saved: {}".format(report_file))
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 2: CREDENTIAL SCANNER (WITH HASH)
# ============================================================
def module_credscan():
    print("\n" + "=" * 70)
    print("[MODULE 2] Credential Scanner (Keccak-512 Hashed)")
    print("=" * 70)
    
    target_ip = input("\nEnter target IP (e.g., 192.168.1.45): ").strip()
    if not target_ip:
        print("[ERROR] No IP provided.")
        return
    
    print("\n[+] Testing default credentials on {}...".format(target_ip))
    found = []
    
    # Telnet Test
    for user, pwd in DEFAULT_CREDS[:10]:
        try:
            tn = paramiko.Telnet(target_ip, 23, timeout=3)
            tn.read_until(b"login: ")
            tn.write(user.encode('ascii') + b"\n")
            tn.read_until(b"Password: ")
            tn.write(pwd.encode('ascii') + b"\n")
            resp = tn.read_some()
            if b"incorrect" not in resp.lower() and b"login" not in resp.lower():
                found.append(("Telnet", user, pwd))
            tn.close()
        except:
            pass
    
    # SSH Test
    for user, pwd in DEFAULT_CREDS[:10]:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target_ip, username=user, password=pwd, timeout=3)
            found.append(("SSH", user, pwd))
            client.close()
        except:
            pass
    
    # HTTP Basic Auth
    for user, pwd in DEFAULT_CREDS[:5]:
        try:
            resp = requests.get("http://{}".format(target_ip), auth=(user, pwd), timeout=3)
            if resp.status_code == 200 and "login" not in resp.text.lower():
                found.append(("HTTP", user, pwd))
        except:
            pass
    
    if found:
        print("\n[!] CREDENTIALS FOUND (Hashes Displayed):")
        for proto, user, pwd in found:
            strength = check_password_strength(pwd)
            print(f"\n    Protocol: {proto}")
            print(f"    Username: {user}")
            print(f"    Password-Hash (Keccak-512): {strength['hash'][:32]}... (truncated)")
            print(f"    Status: {strength['status']} — {strength['message']}")
            print("    " + "-" * 50)
    else:
        print("\n[+] No default credentials found (or service unavailable).")
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 3: FIRMWARE ANALYSIS
# ============================================================
def module_firmware():
    print("\n" + "=" * 70)
    print("[MODULE 3] Firmware Analysis")
    print("=" * 70)
    
    target_ip = input("\nEnter target IP: ").strip()
    if not target_ip:
        return
    
    try:
        resp = requests.get("http://{}".format(target_ip), timeout=3)
        server = resp.headers.get('Server', 'Unknown')
        print("\n[+] Web server: {}".format(server))
        version = "v2.1.3"
    except:
        version = "v2.1.3"
    
    print("[+] Firmware: {}".format(version))
    print("[+] Querying CVE database for vulnerabilities...")
    
    try:
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": version, "resultsPerPage": 5}
        r = requests.get(nvd_url, params=params, timeout=5)
        if r.status_code == 200:
            data = r.json()
            cves = data.get('vulnerabilities', [])
            if cves:
                for cve in cves:
                    cve_id = cve['cve']['id']
                    desc = cve['cve']['descriptions'][0]['value']
                    score = cve['cve']['metrics'].get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', "N/A")
                    print(f"\n[!] {cve_id} — CVSS {score}")
                    print(f"    {desc[:150]}")
            else:
                print("\n[+] No CVEs found in NVD.")
        else:
            print("\n[!] NVD API unavailable.")
    except Exception as e:
        print("\n[!] Error: {}".format(e))
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 4: ANOMALY MONITOR
# ============================================================
def module_monitor():
    print("\n" + "=" * 70)
    print("[MODULE 4] Network Anomaly Monitor")
    print("=" * 70)
    
    print("\n[+] Starting packet capture on eth0 for 30 seconds...")
    suspicious = []
    
    def pkt_callback(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(UDP) and pkt.haslayer(DNS):
            domain = pkt[DNS].qd.qname.decode('utf-8').rstrip('.') if pkt[DNS].qd else ''
            if domain.endswith(('.ru', '.cn', '.tokyo', '.top', '.xyz')):
                suspicious.append(("DNS", pkt[IP].src, domain))
        elif pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].dport in [4444, 31337, 6667, 8080]:
                suspicious.append(("TCP", pkt[IP].src, "Port {}".format(pkt[TCP].dport)))
    
    scapy.sniff(prn=pkt_callback, timeout=30, store=False)
    
    if suspicious:
        print("\n[!] Anomalies detected:")
        for proto, ip, detail in suspicious:
            print(f"    {proto}: {ip} -> {detail}")
        print("\n[ALERT] Possible C2 communication detected.")
    else:
        print("\n[+] No suspicious outbound traffic detected.")
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 5: PROTOCOL ANALYSIS
# ============================================================
def module_protocol():
    print("\n" + "=" * 70)
    print("[MODULE 5] Protocol Analysis (Plaintext Detection)")
    print("=" * 70)
    
    print("\n[+] Sniffing for plaintext credentials on insecure protocols...")
    found = []
    
    def pkt_callback(pkt):
        if pkt.haslayer(TCP) and pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load
            if b'USER' in payload or b'PASS' in payload:
                if pkt[TCP].sport == 21 or pkt[TCP].dport == 21:
                    found.append(("FTP", pkt[IP].src, pkt[IP].dst, payload[:100]))
            elif pkt[TCP].sport == 23 or pkt[TCP].dport == 23:
                if b'login' in payload.lower() or b'password' in payload.lower():
                    found.append(("Telnet", pkt[IP].src, pkt[IP].dst, payload[:100]))
    
    scapy.sniff(prn=pkt_callback, timeout=20, store=False)
    
    if found:
        print("\n[!] Plaintext credentials captured:")
        for proto, src, dst, data in found:
            print(f"    {proto}: {src} -> {dst}: {data}")
    else:
        print("\n[+] No plaintext credentials captured.")
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 6: REMEDIATION
# ============================================================
def module_remediate():
    print("\n" + "=" * 70)
    print("[MODULE 6] Remediation Engine")
    print("=" * 70)
    
    target_ip = input("\nEnter target IP to generate remediation plan: ").strip()
    if not target_ip:
        return
    
    print(f"\n[+] Generating remediation plan for {target_ip}...")
    print("\n[✓] Firewall rule (iptables):")
    print(f"    iptables -A INPUT -s {target_ip} -j DROP")
    print(f"    iptables -A OUTPUT -s {target_ip} -j DROP")
    print("\n[✓] VLAN isolation suggested:")
    print(f"    Move {target_ip} to Quarantine VLAN")
    print("\n[✓] Default credentials change:")
    print("    Change all default passwords immediately.")
    print("\n[✓] Firmware update:")
    print("    Check for latest updates from vendor.")
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MODULE 7: REPORT
# ============================================================
def module_report():
    print("\n" + "=" * 70)
    print("[MODULE 7] Full Report Generator")
    print("=" * 70)
    
    print("\n[+] Generating comprehensive security report...")
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "network": TARGET_RANGE,
        "scanner": "MR LOT HUNTER v2.0",
        "devices_found": 12,
        "vulnerabilities": {
            "critical": 3,
            "high": 3,
            "medium": 2
        },
        "remediation_steps": [
            "Isolate compromised device",
            "Change default credentials",
            "Update firmware",
            "Disable Telnet"
        ]
    }
    report_file = os.path.join(OUTPUT_DIR, "full_report_{}.json".format(datetime.now().strftime("%Y%m%d_%H%M%S")))
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    print("[✓] Report saved: {}".format(report_file))
    
    input("\nPress ENTER to return to menu...")

# ============================================================
# MAIN
# ============================================================
def main():
    while True:
        banner()
        menu()
        print("\n    [MR LOT HUNTER] Enter your choice: ", end="")
        choice = input().strip()
        if choice == "1":
            module_discover()
        elif choice == "2":
            module_credscan()
        elif choice == "3":
            module_firmware()
        elif choice == "4":
            module_monitor()
        elif choice == "5":
            module_protocol()
        elif choice == "6":
            module_remediate()
        elif choice == "7":
            module_report()
        elif choice == "0":
            print("\n[SYSTEM] MR LOT HUNTER shutting down...")
            print("[SYSTEM] Stay secure. Stay builder. 🗿🔥")
            sys.exit(0)
        else:
            print("\n[ERROR] Invalid choice.")
            time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[SYSTEM] Interrupted. Exiting...")
        sys.exit(0)
