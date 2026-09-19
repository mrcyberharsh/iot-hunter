#!/usr/bin/env python3
"""
iot-hunter — defensive IoT security toolkit.

WARNING: Only run this against networks and devices you own or have explicit
written authorisation to test. Unauthorised scanning and credential testing is
illegal in most jurisdictions.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from modules.alerting import Alerter
from modules.anomaly import AnomalyDetector
from modules.compliance import ComplianceMapper
from modules.config import ConfigError, load_config, resolve_interface_and_subnet
from modules.credentials import CredentialTester
from modules.discovery import Discovery, OUIDatabase
from modules.fingerprint import Fingerprinter
from modules.models import Finding
from modules.protocol import ProtocolAnalyzer
from modules.remediation import build_plan, render_plan_text
from modules.reporting import Reporter
from modules.utils import setup_logging

DISCLAIMER = """
+----------------------------------------------------------------------------+
|  iot-hunter — DEFENSIVE USE ONLY                                           |
|                                                                            |
|  This tool performs active network scanning, service fingerprinting and    |
|  credential testing. Run it ONLY against networks and devices that you     |
|  own or have explicit written authorisation to assess.                     |
|                                                                            |
|  Unauthorised use may violate the IT Act 2000 (India), the Computer        |
|  Misuse Act, GDPR/DPDP, and equivalent laws elsewhere. The authors accept  |
|  no liability for misuse.                                                  |
+----------------------------------------------------------------------------+
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗ ██████╗ ████████╗   ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗  ║
║   ██║██╔═══██╗╚══██╔══╝   ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗ ║
║   ██║██║   ██║   ██║      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝ ║
║   ██║██║   ██║   ██║      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗ ║
║   ██║╚██████╔╝   ██║      ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║ ║
║   ╚═╝ ╚═════╝    ╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝ ║
║                                                                              ║
║                         by Mr CyberHarsh  •  v1.0.0                          ║
║                    Defensive IoT Security & GRC Toolkit                      ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
**THIS TOOL MADE BY MR CYBER HARSH**

class Hunter:
    """Holds session state across the interactive menu."""

    def __init__(self, config: Dict[str, Any], args: argparse.Namespace):
        self.config = config
        self.args = args
        self.log = logging.getLogger("iothunter")

        iface_info, network = resolve_interface_and_subnet(config)
        self.interface_info = iface_info
        self.interface: str = iface_info["name"]
        self.network: ipaddress.IPv4Network = network

        oui_path = args.oui_db or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "data", "oui.csv"
        )
        self.oui = OUIDatabase(oui_path)

        self.devices: List[Dict[str, Any]] = []
        self.findings: List[Finding] = []
        self.compliance: Dict[str, Any] = {}
        self.plan: List[Dict[str, Any]] = []

        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        self.finished_at: Optional[str] = None

        self.log.info(
            "Session started | interface=%s ip=%s subnet=%s",
            self.interface, iface_info["ip"], self.network,
        )

    # ------------------------------------------------------------------ #
    def banner(self) -> None:
        print(DISCLAIMER)
        print(f"  Detected interface : {self.interface}  ({self.interface_info['ip']})")
        print(f"  Detected subnet    : {self.network}")
        print(f"  OUI prefixes loaded: {len(self.oui.prefixes)}")
        print()

    # ------------------------------------------------------------------ #
    def _confirm(self, prompt: str) -> bool:
        if self.args.yes:
            return True
        try:
            return input(f"{prompt} [y/N]: ").strip().lower() in ("y", "yes")
        except (EOFError, KeyboardInterrupt):
            return False

    # ------------------------------------------------------------------ #
    def _merge(self, findings: List[Finding]) -> None:
        existing = {f.id for f in self.findings}
        for f in findings:
            if f.id not in existing:
                self.findings.append(f)
                existing.add(f.id)

    # ------------------------------------------------------------------ #
    # Modules
    # ------------------------------------------------------------------ #
    def discover(self) -> None:
        self.log.info("=== Discovery ===")
        if not self._confirm(f"Scan subnet {self.network} on {self.interface}?"):
            print("Aborted.")
            return
        discovery = Discovery(self.config, self.oui)
        devices, findings = discovery.run(self.interface, self.network)
        self.devices = devices
        self._merge(findings)
        print(f"\nDiscovered {len(devices)} device(s):\n")
        for d in devices:
            ports = ", ".join(str(p["port"]) for p in d.get("ports", [])) or "-"
            print(f"  {d['ip']:<16} {d['mac'] or '-':<18} "
                  f"{(d['vendor'] or '-')[:24]:<24} {(d['hostname'] or '-')[:24]:<24} [{ports}]")
        print()

    def fingerprint(self) -> None:
        self.log.info("=== Fingerprinting ===")
        if not self.devices:
            print("Run discovery first.")
            return
        fp = Fingerprinter(self.config)
        findings = fp.run(self.devices)
        self._merge(findings)
        print("\nFingerprint results:\n")
        for d in self.devices:
            print(f"  {d['ip']:<16} {d.get('device_type', '-'):<26} "
                  f"OS={d.get('os', '-'):<16} FW={d.get('firmware', '-')}")
        print()

    def credentials(self) -> None:
        self.log.info("=== Credential Testing ===")
        if not self.devices:
            print("Run discovery first.")
            return
        if not self._confirm(
            "Test default credentials? This performs login attempts against discovered services."
        ):
            return
        tester = CredentialTester(self.config)
        findings = tester.run(self.devices)
        self._merge(findings)
        if findings:
            print(f"\n{len(findings)} device(s) accepted default credentials:\n")
            for f in findings:
                print(f"  [{f.severity.upper()}] {f.asset} — {f.evidence.get('service')} "
                      f"(user: {f.evidence.get('username')})")
        else:
            print("\nNo default credentials were accepted.")
        print()

    def anomaly(self) -> None:
        self.log.info("=== Anomaly Detection ===")
        detector = AnomalyDetector(self.config, self.network)
        acfg = self.config.get("anomaly", {}) or {}

        choice = input(
            "  [1] Learn baseline\n"
            "  [2] Monitor traffic\n"
            "  [3] Both (learn then monitor)\n"
            "Select [1-3]: "
        ).strip()

        findings: List[Finding] = []
        if choice in ("1", "3"):
            minutes = int(input(
                f"Baseline duration in minutes [{acfg.get('baseline_minutes', 60)}]: "
            ).strip() or acfg.get("baseline_minutes", 60))
            detector.learn_baseline(self.interface, minutes * 60)
            print("Baseline learning complete.")

        if choice in ("2", "3"):
            minutes = int(input(
                f"Monitoring duration in minutes [{acfg.get('monitor_minutes', 30)}]: "
            ).strip() or acfg.get("monitor_minutes", 30))
            findings = detector.monitor(self.interface, minutes * 60)
            self._merge(findings)
            print(f"\nMonitoring complete — {len(findings)} anomaly finding(s).")
            for f in findings:
                print(f"  [{f.severity.upper()}] {f.title} — {f.asset}")
        print()

    def protocols(self) -> None:
        self.log.info("=== Protocol Analysis ===")
        minutes = int(input("Passive capture duration in minutes [5]: ").strip() or 5)
        analyzer = ProtocolAnalyzer(self.config)
        findings = analyzer.capture(self.interface, minutes * 60)
        self._merge(findings)
        print(f"\n{len(findings)} protocol finding(s):")
        for f in findings:
            print(f"  [{f.severity.upper()}] {f.title} — {f.asset}")
        print()

    def remediate(self) -> None:
        self.plan = build_plan(self.findings)
        print(render_plan_text(self.plan))

    def compliance_report(self) -> None:
        mapper = ComplianceMapper(self.config)
        self.compliance = mapper.evaluate(self.findings)
        print(f"\nCompliance score: {self.compliance['score']}/100 "
              f"({self.compliance['score_band']})\n")
        s = self.compliance["summary"]
        print(f"  Critical={s['critical']} High={s['high']} Medium={s['medium']} "
              f"Low={s['low']} Info={s['info']} Total={s['total']}")
        if "iso27001" in self.compliance:
            print(f"  ISO 27001 controls triggered: "
                  f"{self.compliance['iso27001']['total_controls_triggered']}")
        if "dpdp" in self.compliance and self.compliance["dpdp"]["notification_required"]:
            print("  DPDP: breach notification likely required (Section 8(6))")
        if "certin" in self.compliance:
            print(f"  CERT-In categories: "
                  f"{len(self.compliance['certin']['categories'])}")
        print()

    def report(self) -> None:
        if not self.compliance:
            self.compliance = ComplianceMapper(self.config).evaluate(self.findings)
        if not self.plan:
            self.plan = build_plan(self.findings)

        self.finished_at = time.strftime("%Y-%m-%d %H:%M:%S")
        session = {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "interface": self.interface,
            "interface_ip": self.interface_info["ip"],
            "subnet": str(self.network),
            "devices": self.devices,
        }
        session_payload = {
            "session": session,
            "findings": [f.to_dict() for f in self.findings],
            "compliance": self.compliance,
            "remediation_plan": self.plan,
        }

        reporter = Reporter(self.config)
        paths = []
        if "json" in reporter.formats:
            paths.append(reporter.export_json(session_payload))
        if "pdf" in reporter.formats:
            try:
                paths.append(
                    reporter.export_pdf(session, self.findings, self.compliance, self.plan)
                )
            except Exception as exc:
                self.log.error("PDF generation failed: %s", exc)
                print(f"  ! PDF generation failed: {exc}")

        for p in paths:
            print(f"  Report written: {p}")

        # --- Alerts ------------------------------------------------------ #
        alerter = Alerter(self.config)
        result = alerter.dispatch(self.findings, context=f"Assessment of {self.network}")
        if result["email"] or result["slack"]:
            print(f"  Alerts sent: email={result['email']} slack={result['slack']}")
        print()

    def full_assessment(self) -> None:
        if not self._confirm(
            f"Run a FULL assessment against {self.network}? "
            "This includes scanning and credential testing."
        ):
            return
        self.discover()
        self.fingerprint()
        if self._confirm("Proceed with default-credential testing?"):
            tester = CredentialTester(self.config)
            self._merge(tester.run(self.devices))
        if self._confirm("Run a 5-minute passive protocol capture?"):
            analyzer = ProtocolAnalyzer(self.config)
            self._merge(analyzer.capture(self.interface, 300))
        self.remediate()
        self.compliance_report()
        self.report()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
MENU = """
================ iot-hunter ================
 1) Discover devices
 2) Fingerprint devices
 3) Test default credentials
 4) Monitor traffic (anomaly detection)
 5) Detect insecure protocols
 6) Build remediation plan
 7) Compliance report (ISO/DPDP/CERT-In)
 8) Generate report (PDF + JSON) + alerts
 9) Full assessment
 0) Exit
============================================
"""


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="iothunter",
        description="iot-hunter — defensive IoT security toolkit",
    )
    p.add_argument("-c", "--config", default="config.yaml",
                   help="Path to config.yaml (default: config.yaml)")
    p.add_argument("-i", "--interface", default=None,
                   help="Override the interface to use (e.g. eth0, wlan0)")
    p.add_argument("-s", "--subnet", default=None,
                   help="Override the subnet to scan (e.g. 192.168.1.0/24)")
    p.add_argument("--oui-db", default=None,
                   help="Path to the offline OUI CSV file")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip confirmation prompts (non-interactive use)")
    p.add_argument("--non-interactive", action="store_true",
                   help="Run the full assessment and exit")
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    if not os.path.isfile(args.config):
        print(f"Configuration file not found: {args.config}", file=sys.stderr)
        return 2

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    if args.interface:
        config["interface"] = args.interface
    if args.subnet:
        config["subnet"] = args.subnet

    setup_logging(config)
    log = logging.getLogger("iothunter")

    try:
        hunter = Hunter(config, args)
    except ConfigError as exc:
        log.error("Startup failed: %s", exc)
        print(f"Startup failed: {exc}", file=sys.stderr)
        return 2

    hunter.banner()
    log.info("iot-hunter started — all actions will be recorded in the audit log")

    if args.non_interactive:
        hunter.full_assessment()
        return 0

    actions = {
        "1": hunter.discover,
        "2": hunter.fingerprint,
        "3": hunter.credentials,
        "4": hunter.anomaly,
        "5": hunter.protocols,
        "6": hunter.remediate,
        "7": hunter.compliance_report,
        "8": hunter.report,
        "9": hunter.full_assessment,
    }

    while True:
        print(MENU)
        try:
            choice = input("Select an option: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if choice == "0":
            break
        action = actions.get(choice)
        if action is None:
            print("Invalid option.\n")
            continue
        try:
            action()
        except KeyboardInterrupt:
            print("\nInterrupted.")
        except Exception as exc:  # keep the CLI alive on module errors
            log.exception("Module error")
            print(f"  ! Error: {exc}\n")

    print("Goodbye.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
