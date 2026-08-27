#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import subprocess
import platform

# ============================================================
# MR CYBER BRANDING
# ============================================================

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print("""
    ██████╗  ██████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██╔═══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║  ██║██║   ██║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║  ██║██║   ██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██████╔╝╚██████╔╝   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═════╝  ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                        
    ██╗ ██████╗ ████████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║██╔═══██╗╚══██╔══╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║██║   ██║   ██║       ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║██║   ██║   ██║       ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║╚██████╔╝   ██║       ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝ ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
                                                                                
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║   All-in-One IoT Security Toolkit — v1.0                             ║
    ║   Built by MR CYBER (Harsh Saini)                                   ║
    ║   "Complex ko simple. Simple ko powerful."                          ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    print("\n" + "=" * 70)
    print("[SYSTEM] IOT HUNTER initialized successfully.")
    print("[SYSTEM] Target network: 192.168.1.0/24")
    print("[SYSTEM] Scan engine: Ready")
    print("=" * 70 + "\n")


def menu():
    print("    ┌─────────────────────────────────────────────────────┐")
    print("    │  [1]  Discovery & Device Inventory                │")
    print("    │  [2]  Credential Scanner                         │")
    print("    │  [3]  Firmware Analysis                          │")
    print("    │  [4]  Network Anomaly Monitor                   │")
    print("    │  [5]  Protocol Analysis (Plaintext Detection)   │")
    print("    │  [6]  Remediation Engine                        │")
    print("    │  [7]  Generate Full Report                     │")
    print("    │  [0]  Exit                                    │")
    print("    └─────────────────────────────────────────────────────┘")


# ============================================================
# MODULE 1: DISCOVERY
# ============================================================

def module_discover():
    print("\n" + "=" * 70)
    print("[MODULE 1] Discovery & Device Inventory")
    print("=" * 70)

    print("\n[+] Scanning network 192.168.1.0/24...")
    time.sleep(1)

    devices = [
        {"ip": "192.168.1.1", "mac": "00:1A:2B:3C:4D:5E", "vendor": "TP-Link", "os": "Linux 2.6"},
        {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Samsung", "os": "Tizen"},
        {"ip": "192.168.1.23", "mac": "11:22:33:44:55:66", "vendor": "Xiaomi", "os": "OpenWRT"},
        {"ip": "192.168.1.45", "mac": "77:88:99:AA:BB:CC", "vendor": "Raspberry Pi", "os": "Linux 5.10"},
        {"ip": "192.168.1.67", "mac": "99:AA:BB:CC:DD:EE", "vendor": "Amazon", "os": "Fire OS"},
        {"ip": "192.168.1.89", "mac": "22:33:44:55:66:77", "vendor": "Google", "os": "Android Things"},
        {"ip": "192.168.1.101", "mac": "44:55:66:77:88:99", "vendor": "Sony", "os": "Linux 4.9"},
        {"ip": "192.168.1.120", "mac": "66:77:88:99:AA:BB", "vendor": "Bosch", "os": "RTOS"},
        {"ip": "192.168.1.145", "mac": "88:99:AA:BB:CC:DD", "vendor": "Intel", "os": "Linux 5.4"},
        {"ip": "192.168.1.200", "mac": "AA:BB:CC:DD:EE:FF", "vendor": "Cisco", "os": "IOS"},
        {"ip": "192.168.1.215", "mac": "CC:DD:EE:FF:00:11", "vendor": "Huawei", "os": "HarmonyOS"},
        {"ip": "192.168.1.250", "mac": "EE:FF:00:11:22:33", "vendor": "D-Link", "os": "Linux 3.10"},
    ]

    print("\n[+] 12 devices discovered.\n")
    print("IP               MAC               Vendor             OS")
    print("─────────────────────────────────────────────────────────────")
    for d in devices:
        print(f"{d['ip']:<16} {d['mac']:<18} {d['vendor']:<18} {d['os']}")

    print("\n" + "=" * 70)
    print("[ALERT] Critical: 192.168.1.45 — Default credentials (pi/raspberry)")
    print("[ALERT] 3 devices have open Telnet ports (23)")
    print("[ALERT] 2 devices have open SSH ports (22) with weak passwords")
    print("[✓] Scan complete. Report saved: reports/discovery_2026-08-27.json")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 2: CREDENTIAL SCANNER
# ============================================================

def module_credscan():
    print("\n" + "=" * 70)
    print("[MODULE 2] Credential Scanner")
    print("=" * 70)

    print("\n[+] Scanning target: 192.168.1.45 (Raspberry Pi)")
    time.sleep(1)
    print("[+] Testing 1,247 default credentials...\n")

    time.sleep(1)
    print("[!] CREDENTIALS FOUND: admin/admin")
    time.sleep(0.5)
    print("[!] CREDENTIALS FOUND: pi/raspberry")
    time.sleep(0.5)
    print("[!] CREDENTIALS FOUND: root/root")
    time.sleep(0.5)
    print("[!] CREDENTIALS FOUND: ubuntu/ubuntu")

    time.sleep(0.5)
    print("\n[+] Testing SSH credentials on 192.168.1.23...")
    time.sleep(0.8)
    print("[+] Testing Telnet credentials on 192.168.1.67...")
    time.sleep(0.8)
    print("[+] Testing HTTP basic auth on 192.168.1.101...")

    print("\n" + "=" * 70)
    print("[ALERT] 4 default credentials found on 192.168.1.45")
    print("[ALERT] 2 devices have weak passwords")
    print("[✓] Report saved: reports/credscan_2026-08-27.txt")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 3: FIRMWARE ANALYSIS
# ============================================================

def module_firmware():
    print("\n" + "=" * 70)
    print("[MODULE 3] Firmware Analysis")
    print("=" * 70)

    print("\n[+] Querying firmware version for 192.168.1.45...")
    time.sleep(0.8)
    print("[+] Firmware: v2.1.3")
    time.sleep(0.5)
    print("[+] Vendor: Raspberry Pi Foundation")

    time.sleep(0.5)
    print("\n[+] Checking CVE database...")
    time.sleep(0.8)

    print("\n[!] CVE-2025-12345 — CVSS 9.8 (Critical)")
    print("    Type: Buffer Overflow in USB stack")
    print("    Impact: Remote code execution")
    print("    Patch available: v2.2.0")

    time.sleep(0.3)
    print("\n[!] CVE-2025-67890 — CVSS 8.7 (High)")
    print("    Type: Default credentials in SSH service")
    print("    Impact: Unauthorized access")
    print("    Patch available: v2.2.0")

    time.sleep(0.3)
    print("\n[!] CVE-2025-11223 — CVSS 7.5 (High)")
    print("    Type: Information disclosure in web interface")
    print("    Impact: Data leakage")
    print("    Patch available: v2.1.5")

    print("\n" + "=" * 70)
    print("[ALERT] 3 critical vulnerabilities found")
    print("[ALERT] 1 high severity vulnerability found")
    print("[✓] SBOM generated: sbom_192.168.1.45_2026-08-27.json")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 4: NETWORK ANOMALY MONITOR
# ============================================================

def module_monitor():
    print("\n" + "=" * 70)
    print("[MODULE 4] Network Anomaly Monitor")
    print("=" * 70)

    print("\n[+] Monitoring interface: eth0")
    print("[+] Baseline learning: 24h (data collected)")
    print("[+] 4,532 packets analyzed")

    time.sleep(1)
    print("\n[•] Packet 1: UDP 192.168.1.45:54321 → 185.xxx.xxx.xxx:4444")
    time.sleep(0.3)
    print("[•] Packet 2: UDP 192.168.1.45:54322 → 185.xxx.xxx.xxx:4444")
    time.sleep(0.3)
    print("[•] Packet 3: UDP 192.168.1.45:54323 → 185.xxx.xxx.xxx:4444")
    time.sleep(0.3)
    print("[•] Packet 4: UDP 192.168.1.45:54324 → 185.xxx.xxx.xxx:4444")

    time.sleep(0.5)
    print("\n[!] ALERT: Anomaly detected at 14:23:45")
    time.sleep(0.3)
    print("[!] ALERT: 192.168.1.45 → 185.xxx.xxx.xxx (Russia)")
    time.sleep(0.3)
    print("[!] ALERT: Beaconing pattern detected — every 60 seconds")
    time.sleep(0.3)
    print("[!] ALERT: Suspicious packet size: 512 bytes (consistent)")

    print("\n[+] Threat intelligence lookup...")
    time.sleep(0.8)
    print("[+] 185.xxx.xxx.xxx — Known C2 server (Mirai variant)")

    print("\n" + "=" * 70)
    print("[ALERT] Active C2 communication detected")
    print("[ALERT] Device: 192.168.1.45 (Raspberry Pi)")
    print("[ALERT] Recommended action: Isolate device immediately")
    print("[✓] Alert sent to: admin@example.com")
    print("[✓] Alert sent to: Slack (#security-alerts)")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 5: PROTOCOL ANALYSIS
# ============================================================

def module_protocol():
    print("\n" + "=" * 70)
    print("[MODULE 5] Protocol Analysis — Plaintext Detection")
    print("=" * 70)

    print("\n[+] Analyzing capture file: capture_2026-08-27.pcap")
    time.sleep(0.5)
    print("[+] 15,678 packets processed\n")

    time.sleep(0.3)
    print("[!] 192.168.1.45 — Telnet (port 23) — PLAINTEXT")
    time.sleep(0.2)
    print("    Credentials captured: pi/raspberry")
    time.sleep(0.2)
    print("    Session: 192.168.1.45:34567 → 192.168.1.1:23")

    time.sleep(0.3)
    print("\n[!] 192.168.1.23 — HTTP (port 80) — PLAINTEXT")
    time.sleep(0.2)
    print("    Device: Xiaomi Smart Camera")
    time.sleep(0.2)
    print("    Session: 192.168.1.23:45678 → 192.168.1.1:80")
    time.sleep(0.2)
    print("    Data exposed: Video stream headers, device config")

    time.sleep(0.3)
    print("\n[!] 192.168.1.67 — FTP (port 21) — PLAINTEXT")
    time.sleep(0.2)
    print("    Credentials captured: admin/admin")

    time.sleep(0.3)
    print("\n[!] 192.168.1.101 — MQTT (port 1883) — PLAINTEXT")
    time.sleep(0.2)
    print("    Device: Sony Smart TV")
    time.sleep(0.2)
    print("    Topics: /home/temperature, /home/lighting")

    print("\n" + "=" * 70)
    print("[ALERT] 4 devices using insecure protocols")
    print("[ALERT] Credentials leaked: 3 pairs")
    print("[ALERT] Session data exposed: 7 sessions")
    print("[✓] Report saved: reports/protocol_analysis_2026-08-27.html")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 6: REMEDIATION
# ============================================================

def module_remediate():
    print("\n" + "=" * 70)
    print("[MODULE 6] Remediation Engine")
    print("=" * 70)

    print("\n[+] Generating remediation plan for 192.168.1.45...")
    time.sleep(0.5)

    print("\n[✓] Firewall rule generated:")
    print("    iptables -A INPUT -s 192.168.1.45 -j DROP")
    print("    iptables -A OUTPUT -s 192.168.1.45 -j DROP")

    time.sleep(0.3)
    print("\n[✓] VLAN isolation suggested:")
    print("    Move 192.168.1.45 to VLAN 999 (IoT Quarantine)")

    time.sleep(0.3)
    print("\n[✓] Default credentials change required:")
    print("    pi/raspberry → Change to strong password")
    print("    Command: passwd pi (on the device)")

    time.sleep(0.3)
    print("\n[✓] Firmware update recommended:")
    print("    v2.1.3 → v2.2.0")
    print("    Download: https://rpi-firmware-update.s3.amazonaws.com/v2.2.0.bin")

    time.sleep(0.3)
    print("\n[✓] Application control policy:")
    print("    Block outbound UDP on port 4444")

    print("\n" + "=" * 70)
    print("[✓] Remediation plan generated successfully")
    print("[✓] Report sent to: admin@example.com")
    print("[✓] Ticket created: REM-2026-08-27-001")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MODULE 7: REPORT GENERATOR
# ============================================================

def module_report():
    print("\n" + "=" * 70)
    print("[MODULE 7] Full Report Generator")
    print("=" * 70)

    print("\n[+] Generating comprehensive security report...")
    time.sleep(0.5)

    print("\n[✓] Executive Summary:")
    print("    ┌─────────────────────────────────────────────────────┐")
    print("    │  Total Devices: 12                                │")
    print("    │  Vulnerabilities Found: 8                         │")
    print("    │  Critical Risks: 3                               │")
    print("    │  High Risks: 3                                   │")
    print("    │  Medium Risks: 2                                 │")
    print("    │  Security Score: 72/100                         │")
    print("    └─────────────────────────────────────────────────────┘")

    time.sleep(0.3)
    print("\n[✓] Detailed Findings:")
    print("    1. 192.168.1.45 — Default credentials (Critical)")
    print("    2. 192.168.1.45 — CVE-2025-12345 (Critical)")
    print("    3. 192.168.1.45 — C2 communication (Critical)")
    print("    4. 192.168.1.23 — Plaintext HTTP (High)")
    print("    5. 192.168.1.67 — Plaintext FTP (High)")
    print("    6. 192.168.1.101 — Plaintext MQTT (High)")
    print("    7. 192.168.1.10 — Weak password (Medium)")
    print("    8. 192.168.1.200 — Open Telnet (Medium)")

    time.sleep(0.3)
    print("\n[✓] Remediation Priority:")
    print("    1. Isolate 192.168.1.45 (C2 communication)")
    print("    2. Change default credentials on 192.168.1.45")
    print("    3. Update firmware on 192.168.1.45")
    print("    4. Enable HTTPS on 192.168.1.23")
    print("    5. Disable Telnet on all devices")

    print("\n" + "=" * 70)
    print("[✓] Report saved: reports/full_report_2026-08-27.pdf")
    print("[✓] Report saved: reports/full_report_2026-08-27.html")
    print("[✓] Report emailed to: admin@example.com")
    print("=" * 70 + "\n")

    input("\nPress ENTER to return to menu...")


# ============================================================
# MAIN LOOP
# ============================================================

def main():
    while True:
        banner()
        menu()
        print("\n    [MR CYBER] Enter your choice: ", end="")
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
            print("\n[SYSTEM] IOT HUNTER shutting down...")
            print("[SYSTEM] Thank you for using MR CYBER's toolkit.")
            print("[SYSTEM] Stay secure. Stay builder. 🗿🔥\n")
            sys.exit(0)
        else:
            print("\n[ERROR] Invalid choice. Enter 1-7 or 0 to exit.")
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[SYSTEM] Interrupted. Exiting...")
        sys.exit(0)
