"""Defensive, human-readable IoT remediation recommendations."""
from __future__ import annotations
from typing import Any


def build_remediation_plan(protocol_findings: list[dict[str, Any]] | None = None,
                           credential_findings: list[dict[str, Any]] | None = None,
                           anomaly_findings: list[dict[str, Any]] | None = None) -> list[dict[str, str]]:
    """Turn observed indicators into safe administrative actions, not exploit steps."""
    plan = []
    for finding in protocol_findings or []:
        protocol = str(finding.get("protocol", "legacy protocol"))
        port = finding.get("port", "unknown")
        plan.append({
            "priority": "high" if str(finding.get("risk", "")).lower() == "high" else "medium",
            "finding": f"{protocol} observed on port {port}",
            "fix": "Confirm the service is required. Disable it if unused; otherwise restrict access to trusted management networks and use an encrypted replacement where available.",
            "commands": [],
        })
    for finding in credential_findings or []:
        plan.append({
            "priority": "critical",
            "finding": f"Credential exposure was reported for {finding.get('ip', 'a device')}",
            "fix": "Rotate the affected credential immediately, remove shared/default credentials, and review authentication logs. Do not include the secret in exported reports.",
            "commands": [],
        })
    for finding in anomaly_findings or []:
        kind = str(finding.get("type", "network anomaly")).replace("_", " ")
        plan.append({
            "priority": "high",
            "finding": f"Traffic anomaly observed: {kind}",
            "fix": "Review device and network logs, verify whether the traffic is expected, and isolate the device through normal network administration procedures if compromise is suspected.",
            "commands": [],
        })
    return plan
