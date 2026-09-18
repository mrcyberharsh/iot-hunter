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
    "anomaly_ex
