#!/usr/bin/env python3
"""
IoT Hunter - Defensive IoT Security Toolkit
Built by MR CYBER (Harsh Saini)
"Complex ko Simple. Simple ko Powerful."
"""
import os
import sys
import logging
import platform
import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules import discovery, fingerprint, credentials, anomaly, protocol, remediation, reporting

VERSION = "v2.0"

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
    with open(path, "r") as f:
        return yaml.safe_load(f)


def setup_logging(config):
    log_path = config.get("log_path", "logs/iothunter.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logging.basicConfig(
        filename=log_path,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger().addHandler(logging.StreamHandler(sys.stdout)) if os.environ.get("IOTHUNTER_DEBUG") else None


def disclaimer_prompt():
    print("\nDISCLAIMER: Only scan networks and devices you own or are")
    print("explicitly authorized to test. Unauthorized scanning may be illegal.")
    resp = input("Type YES to confirm you are authorized to scan this network: ").strip()
    return resp.upper() == "YES"


def menu():
    print("""
Select an option:
  1) Full scan (discovery + fingerprint + protocol + anomaly + credentials + report)
  2) Discovery only
  3) Protocol scan only
  4) Anomaly monitor only
  5) Exit
""")
    return input("Choice: ").strip()


def run_full_scan(config):
    logging.info("Starting full scan on platform=%s", platform.system())
    disc = discovery.run_discovery(config)
    devices = fingerprint.run_fingerprint(disc["devices"])

    print("[*] Testing default credentials (rate-limited, local wordlist only)...")
    cred_findings = credentials.run_credential_tests(
        devices, config.get("wordlist_path"), config["credentials"]["max_attempts_per_service"]
    )

    print("[*] Scanning for insecure protocols (30s live capture)...")
    try:
        proto_findings = protocol.run_protocol_scan(duration_sec=30)
    except RuntimeError as e:
        print(f"[!] {e}")
        proto_findings = []

    print("[*] Monitoring traffic for anomalies...")
    try:
        anomaly_findings = anomaly.run_anomaly_monitor(config)
    except RuntimeError as e:
        print(f"[!] {e}")
        anomaly_findings = []

    plan = remediation.build_remediation_plan(proto_findings, cred_findings, anomaly_findings)

    data = {
        "discovery": {"interface": disc["interface"], "subnet": disc["subnet"], "devices": devices},
        "credential_findings": cred_findings,
        "protocol_findings": proto_findings,
        "anomaly_findings": anomaly_findings,
        "remediation_plan": plan,
    }

    json_path, pdf_path = reporting.generate_reports(data, config.get("report_path", "reports/"))
    print(f"\n[+] Reports saved:\n    JSON: {json_path}\n    PDF:  {pdf_path}")
    logging.info("Full scan complete. Reports: %s, %s", json_path, pdf_path)


def main():
    show_banner()
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
            for d in devices:
                print(d)
        elif choice == "3":
            try:
                findings = protocol.run_protocol_scan(duration_sec=30)
                for f in findings:
                    print(f)
            except RuntimeError as e:
                print(f"[!] {e}")
        elif choice == "4":
            try:
                alerts = anomaly.run_anomaly_monitor(config)
                for a in alerts:
                    print(a)
            except RuntimeError as e:
                print(f"[!] {e}")
        elif choice == "5":
            print("Goodbye. Stay secure.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
