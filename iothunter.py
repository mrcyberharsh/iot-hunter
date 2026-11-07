#!/usr/bin/env python3
"""
IoT Hunter - Defensive IoT Security Toolkit
Built by MR CYBER (Harsh Saini)
"Complex ko Simple. Simple ko Powerful."
"""

import argparse
import os
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import anomaly, discovery, fingerprint, inventory, protocol, remediation, reporting
from modules.firmware import scan_firmware_file

VERSION = "v3.1"

BANNER = r"""
 _____ ____ _____   _   _ _   _ _   _ _____ _____ ____
|_   _/ __ \_   _| | | | | | | | \ | |_   _| ____|  _ \
  | || |  | || |   | |_| | | | |  \| | | | |  _| | |_) |
  | || |__| || |   |  _  | |_| | |\  | | | | |___|  _ <
  |_| \____/ |_|   |_| |_|\___/|_| \_| |_| |_____|_| \_\
"""


def show_banner():
    print(BANNER)
    print(f"                IOT HUNTER {VERSION}")
    print("        Built by MR CYBER (Harsh Saini)")
    print("        GitHub: github.com/mrcyberharsh/iot-hunter")
    print("        \"Complex ko Simple. Simple ko Powerful.\"")
    print("-" * 60)


def load_config(path="config.yaml"):
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def setup_logging(config):
    log_path = config.get("log_path", "logs/iothunter.log")
    log_dir = os.path.dirname(log_path)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
    logging = __import__("logging")
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def disclaimer_prompt():
    print("\nDISCLAIMER: Only scan networks and devices you own or are")
    print("explicitly authorized to test. Unauthorized scanning may be illegal.")
    resp = input("Type YES to confirm you are authorized to scan this network: ").strip()
    return resp.upper() == "YES"


def menu():
    print(
        """
Select an option:
  1) Full scan (discovery + fingerprint + inventory history + protocol + anomaly + report)
  2) Discovery only
  3) Protocol scan only
  4) Anomaly monitor only
  5) Exit
"""
    )
    return input("Choice: ").strip()


def run_full_scan(config):
    import logging

    logging.info("Starting full scan")
    disc = discovery.run_discovery(config)
    devices = fingerprint.run_fingerprint(disc["devices"])

    # Active credential guessing is intentionally disabled in the default workflow.
    # Administrators should audit credentials through their approved device-management process.
    cred_findings = []
    print("[*] Credential checks skipped (use your approved administrative audit process).")

    inventory_summary = inventory.record_inventory(
        devices,
        config.get("inventory_history_path", "data/inventory-history.json"),
    )
    print(
        f"[*] Inventory history: {inventory_summary['new_devices']} new, "
        f"{inventory_summary['missing_devices']} missing, "
        f"{inventory_summary['changed_devices']} changed device(s)."
    )

    print("[*] Scanning for insecure protocols (30s live capture)...")
    try:
        proto_findings = protocol.run_protocol_scan(duration_sec=30)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        proto_findings = []

    print("[*] Monitoring traffic for anomalies...")
    try:
        anomaly_findings = anomaly.run_anomaly_monitor(config)
    except RuntimeError as exc:
        print(f"[!] {exc}")
        anomaly_findings = []

    plan = remediation.build_remediation_plan(proto_findings, cred_findings, anomaly_findings)

    data = {
        "discovery": {"interface": disc["interface"], "subnet": disc["subnet"], "devices": devices},
        "credential_findings": cred_findings,
        "protocol_findings": proto_findings,
        "anomaly_findings": anomaly_findings,
        "remediation_plan": plan,
        "inventory_history": inventory_summary,
    }

    json_path, pdf_path = reporting.generate_reports(data, config.get("report_path", "reports/"))
    print(f"\n[+] Reports saved:\n    JSON: {json_path}\n    PDF:  {pdf_path}")
    logging.info("Full scan complete. Reports: %s, %s", json_path, pdf_path)


def parse_args():
    parser = argparse.ArgumentParser(description="IoT Hunter - Defensive IoT Security Toolkit")
    parser.add_argument("--version", action="store_true", help="Show IoT Hunter version and exit.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug logging.")
    parser.add_argument("--firmware", help="Path to a firmware image (.bin, .img, .tar, .squashfs).")
    return parser.parse_args()


def main():
    args = parse_args()
    show_banner()

    if args.version:
        print(f"IoT Hunter {VERSION}")
        return

    if args.firmware:
        findings = scan_firmware_file(args.firmware)
        if not findings:
            print(f"[+] No secret patterns found in {args.firmware}")
            return
        for finding in findings:
            print(
                f"[!] {finding['type']} | file={finding['file']} | "
                f"offset={finding['offset']} | match={finding['match'][:80]}"
            )
        return

    if not os.path.exists("config.yaml"):
        print("[!] config.yaml not found. Please create one (see config.yaml example).")
        sys.exit(1)

    config = load_config()
    setup_logging(config)

    if not disclaimer_prompt():
        print("Authorization not confirmed. Exiting.")
        sys.exit(0)

    while True:
        choice = menu()
        if choice == "1":
            run_full_scan(config)
        elif choice == "2":
            disc = discovery.run_discovery(config)
            devices = fingerprint.run_fingerprint(disc["devices"])
            for device in devices:
                print(device)
        elif choice == "3":
            try:
                findings = protocol.run_protocol_scan(duration_sec=30)
                for finding in findings:
                    print(finding)
            except RuntimeError as exc:
                print(f"[!] {exc}")
        elif choice == "4":
            try:
                alerts = anomaly.run_anomaly_monitor(config)
                for alert in alerts:
                    print(alert)
            except RuntimeError as exc:
                print(f"[!] {exc}")
        elif choice == "5":
            print("Goodbye. Stay secure.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
