"""Map findings to ISO 27001:2022, DPDP Act 2023 and CERT-In requirements."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Set

from .models import Finding, SEVERITY_ORDER

log = logging.getLogger(__name__)


ISO27001_CONTROLS: Dict[str, str] = {
    "A.5.9":  "Inventory of information and other associated assets",
    "A.5.15": "Access control",
    "A.5.17": "Authentication information",
    "A.5.24": "Information security incident management planning and preparation",
    "A.5.25": "Assessment and decision on information security events",
    "A.5.26": "Response to information security incidents",
    "A.5.27": "Learning from information security incidents",
    "A.5.28": "Collection of evidence",
    "A.8.5":  "Secure authentication",
    "A.8.8":  "Management of technical vulnerabilities",
    "A.8.9":  "Configuration management",
    "A.8.16": "Monitoring activities",
    "A.8.19": "Installation of software on operational systems",
    "A.8.20": "Networks security",
    "A.8.21": "Security of network services",
    "A.8.22": "Segregation of networks",
    "A.8.24": "Use of cryptography",
}

ISO27001_MAP: Dict[str, List[str]] = {
    "network_discovery":     ["A.5.9", "A.8.9", "A.8.20"],
    "exposed_service":       ["A.8.20", "A.8.21", "A.8.22"],
    "insecure_protocol":     ["A.8.21", "A.8.24", "A.5.15"],
    "default_credentials":   ["A.5.17", "A.8.5"],
    "plaintext_credentials": ["A.5.17", "A.8.24"],
    "anomaly_beaconing":     ["A.8.16", "A.5.24", "A.5.25"],
    "anomaly_portscan":      ["A.8.16", "A.5.25"],
    "anomaly_exfiltration":  ["A.8.16", "A.5.25", "A.5.26", "A.5.28"],
    "anomaly_protocol":      ["A.8.16"],
    "anomaly_new_destination": ["A.8.16", "A.8.20"],
    "web_hardening":         ["A.8.9", "A.8.20"],
    "firmware":              ["A.8.8", "A.8.19"],
    "scan_error":            ["A.8.16"],
}

DPDP_MAP: Dict[str, List[str]] = {
    "default_credentials":   ["Section 8(5) — reasonable security safeguards"],
    "insecure_protocol":     ["Section 8(5) — reasonable security safeguards"],
    "plaintext_credentials": ["Section 8(5) — reasonable security safeguards"],
    "anomaly_exfiltration":  ["Section 8(6) — personal data breach notification"],
    "anomaly_beaconing":     ["Section 8(5), 8(6)"],
    "exposed_service":       ["Section 8(5)"],
    "firmware":              ["Section 8(5)"],
}

CERTIN_MAP: Dict[str, List[str]] = {
    "anomaly_beaconing":     ["Botnet / C2 communication", "IoT device compromise"],
    "anomaly_portscan":      ["Network scanning / probing"],
    "anomaly_exfiltration":  ["Data breach", "Unauthorised access"],
    "anomaly_protocol":      ["Suspicious network activity"],
    "default_credentials":   ["Unauthorised access"],
    "insecure_protocol":     ["Vulnerable service exposure"],
    "exposed_service":       ["Vulnerable service exposure"],
}

# Score deductions per unique category (highest severity in that category)
_SCORE_WEIGHTS = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}


class ComplianceMapper:
    def __init__(self, config: Dict[str, Any]):
        ccfg = config.get("compliance", {}) or {}
        self.enabled = {
            "iso27001": bool(ccfg.get("iso27001", True)),
            "dpdp": bool(ccfg.get("dpdp", True)),
            "certin": bool(ccfg.get("certin", True)),
        }
        self.organisation = ccfg.get("organisation", "Organisation")

    # ------------------------------------------------------------------ #
    def evaluate(self, findings: List[Finding]) -> Dict[str, Any]:
        iso_hits: Dict[str, List[str]] = {}
        dpdp_hits: Dict[str, List[str]] = {}
        certin_hits: Dict[str, List[str]] = {}

        for f in findings:
            for ctrl in ISO27001_MAP.get(f.category, []):
                iso_hits.setdefault(ctrl, []).append(f.id)
            for sect in DPDP_MAP.get(f.category, []):
                dpdp_hits.setdefault(sect, []).append(f.id)
            for cat in CERTIN_MAP.get(f.category, []):
                certin_hits.setdefault(cat, []).append(f.id)

        score = self._score(findings)

        report: Dict[str, Any] = {
            "organisation": self.organisation,
            "score": score,
            "score_band": self._band(score),
            "summary": self._summary(findings),
        }

        if self.enabled["iso27001"]:
            report["iso27001"] = {
                "controls_triggered": [
                    {
                        "control": c,
                        "title": ISO27001_CONTROLS.get(c, ""),
                        "findings": sorted(set(ids)),
                    }
                    for c, ids in sorted(iso_hits.items())
                ],
                "total_controls_triggered": len(iso_hits),
            }

        if self.enabled["dpdp"]:
            report["dpdp"] = {
                "obligations_triggered": [
                    {"reference": s, "findings": sorted(set(ids))}
                    for s, ids in sorted(dpdp_hits.items())
                ],
                "notification_required": any(
                    f.category == "anomaly_exfiltration" for f in findings
                ),
            }

        if self.enabled["certin"]:
            report["certin"] = {
                "categories": [
                    {"category": c, "findings": sorted(set(ids))}
                    for c, ids in sorted(certin_hits.items())
                ],
                "reporting_deadline_hours": 6,
                "portal": "https://www.cert-in.org.in/",
            }

        return report

    # ------------------------------------------------------------------ #
    def _score(self, findings: List[Finding]) -> int:
        highest: Dict[str, str] = {}
        for f in findings:
            cur = highest.get(f.category, "info")
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[cur]:
                highest[f.category] = f.severity
        deduction = sum(_SCORE_WEIGHTS.get(sev, 0) for sev in highest.values())
        return max(0, 100 - deduction)

    @staticmethod
    def _band(score: int) -> str:
        if score >= 90:
            return "Excellent"
        if score >= 75:
            return "Good"
        if score >= 60:
            return "Fair"
        if score >= 40:
            return "Poor"
        return "Critical"

    @staticmethod
    def _summary(findings: List[Finding]) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            summary[f.severity] = summary.get(f.severity, 0) + 1
        summary["total"] = len(findings)
        return summary
