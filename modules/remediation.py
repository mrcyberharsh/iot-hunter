"""Map findings to concrete, prioritised remediation steps."""
from __future__ import annotations

import logging
from typing import Any, Dict, List

from .models import Finding, SEVERITY_ORDER

log = logging.getLogger(__name__)


# category -> {title, steps[], priority}
PLAYBOOK: Dict[str, Dict[str, Any]] = {
    "default_credentials": {
        "title": "Replace default credentials",
        "priority": "P1",
        "steps": [
            "Log in to the device's management UI immediately and change the admin password.",
            "Set a unique, 16+ character passphrase; never reuse across devices.",
            "Disable any guest/anonymous accounts and unused service accounts.",
            "Where supported, enable certificate-based or MFA authentication.",
            "For MQTT brokers: set `allow_anonymous false` and configure per-device credentials.",
            "Example (Mosquitto) — /etc/mosquitto/conf.d/auth.conf:\n"
            "    allow_anonymous false\n"
            "    password_file /etc/mosquitto/passwd\n"
            "  then: mosquitto_passwd -c /etc/mosquitto/passwd <user>",
        ],
    },
    "insecure_protocol": {
        "title": "Disable or tunnel insecure protocols",
        "priority": "P1",
        "steps": [
            "Disable Telnet/FTP and replace with SSH/SFTP where the device supports it.",
            "Enable TLS on the management UI (HTTPS) and redirect port 80 to 443.",
            "For MQTT, migrate from 1883 to 8883 with TLS and server certificate pinning.",
            "Block legacy ports at the network boundary until devices are upgraded.",
            "Example (Linux firewall):\n"
            "    iptables -A INPUT -p tcp --dport 23 -j DROP\n"
            "    iptables -A INPUT -p tcp --dport 21 -j DROP\n"
            "    iptables -A INPUT -p tcp --dport 1883 -j DROP",
        ],
    },
    "plaintext_credentials": {
        "title": "Eliminate cleartext credential transmission",
        "priority": "P1",
        "steps": [
            "Rotate every credential observed in cleartext — treat them as compromised.",
            "Replace the affected protocol with its TLS equivalent (HTTPS/SFTP/SSH/IMAPS).",
            "Enforce HTTPS-only access via HSTS or a reverse proxy.",
            "Capture again after remediation to confirm no plaintext auth remains.",
        ],
    },
    "exposed_service": {
        "title": "Reduce exposed attack surface",
        "priority": "P2",
        "steps": [
            "Place IoT devices on an isolated VLAN with no inbound Internet access.",
            "Restrict management interfaces to a dedicated admin subnet.",
            "Example (VLAN + firewall):\n"
            "    iptables -A FORWARD -i iot0 -o wan0 -j DROP\n"
            "    iptables -A FORWARD -i iot0 -o lan0 -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
            "    iptables -A FORWARD -i iot0 -o lan0 -j DROP",
            "Disable UPnP/SSDP on the router and on the devices themselves.",
            "Disable unused services (RTSP, SMB, VNC) in the device configuration.",
        ],
    },
    "anomaly_beaconing": {
        "title": "Investigate possible command-and-control beaconing",
        "priority": "P1",
        "steps": [
            "Isolate the source device from the network immediately.",
            "Capture a full PCAP of the traffic and preserve it as evidence.",
            "Identify the destination and block it at the egress firewall:\n"
            "    iptables -A OUTPUT -d <DESTINATION> -j DROP",
            "Re-image the device from vendor-supplied firmware (do not trust in-place cleaning).",
            "Report the incident per CERT-In directions (within 6 hours of detection).",
        ],
    },
    "anomaly_portscan": {
        "title": "Investigate internal port scanning",
        "priority": "P2",
        "steps": [
            "Identify the scanning host and confirm whether it is authorised.",
            "If unauthorised, isolate the host and run a full malware scan / re-image.",
            "Enable switch port security and DHCP snooping on the access layer.",
            "Segment IoT devices so a single compromised device cannot scan the corporate LAN.",
        ],
    },
    "anomaly_exfiltration": {
        "title": "Investigate possible data exfiltration",
        "priority": "P1",
        "steps": [
            "Capture and preserve the evidence PCAP.",
            "Identify what data was transferred and to which destination.",
            "Block the destination and rotate any credentials the device held.",
            "Notify the Data Protection Officer — DPDP Act breach notification may apply.",
            "Report to CERT-In within 6 hours as required by the 2022 directions.",
        ],
    },
    "anomaly_protocol": {
        "title": "Investigate unexpected protocol usage",
        "priority": "P3",
        "steps": [
            "Confirm whether the protocol is legitimate for the device's function.",
            "If not, disable the corresponding service on the device.",
            "Restrict the protocol at the firewall:\n"
            "    iptables -A FORWARD -p <proto> -j DROP",
        ],
    },
    "anomaly_new_destination": {
        "title": "Review new external communications",
        "priority": "P3",
        "steps": [
            "Verify the destination belongs to the device vendor's cloud service.",
            "If unrecognised, block egress and investigate the device.",
            "Apply default-deny egress filtering for IoT VLANs.",
        ],
    },
    "web_hardening": {
        "title": "Harden the device web interface",
        "priority": "P3",
        "steps": [
            "Update device firmware to the latest vendor release.",
            "Front the device with a reverse proxy that adds security headers.",
            "Restrict management UI access to the admin subnet only.",
        ],
    },
    "firmware": {
        "title": "Update firmware and remove unsupported devices",
        "priority": "P2",
        "steps": [
            "Check the vendor's advisory page for the identified firmware version.",
            "Apply the latest stable firmware; schedule regular update windows.",
            "For end-of-support devices, replace or isolate them on a dedicated VLAN.",
        ],
    },
    "network_discovery": {
        "title": "Maintain an accurate asset inventory",
        "priority": "P3",
        "steps": [
            "Record every discovered device in the asset register (ISO 27001 A.5.9).",
            "Re-run discovery monthly and after any network change.",
            "Tag unknown devices for manual review.",
        ],
    },
    "scan_error": {
        "title": "Resolve scanning issues",
        "priority": "P4",
        "steps": [
            "Verify nmap is installed and reachable on PATH.",
            "Confirm the scanning host has root / CAP_NET_RAW privileges.",
            "Check for firewall rules blocking ARP or ICMP.",
        ],
    },
}


def build_plan(findings: List[Finding]) -> List[Dict[str, Any]]:
    """Group findings by category and return an ordered remediation plan."""
    grouped: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        cat = f.category
        play = PLAYBOOK.get(cat)
        if play is None:
            play = {
                "title": f"Review finding: {f.title}",
                "priority": "P4",
                "steps": ["Investigate manually; no automated playbook is available."],
            }
        entry = grouped.setdefault(
            cat,
            {
                "category": cat,
                "title": play["title"],
                "priority": play["priority"],
                "steps": play["steps"],
                "affected_assets": set(),
                "highest_severity": "info",
                "finding_ids": [],
            },
        )
        if f.asset:
            entry["affected_assets"].add(f.asset)
        entry["finding_ids"].append(f.id)
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[entry["highest_severity"]]:
            entry["highest_severity"] = f.severity

    plan = []
    for entry in grouped.values():
        entry["affected_assets"] = sorted(entry["affected_assets"])
        plan.append(entry)

    plan.sort(key=lambda e: (e["priority"], -SEVERITY_ORDER[e["highest_severity"]]))
    return plan


def render_plan_text(plan: List[Dict[str, Any]]) -> str:
    lines = []
    for item in plan:
        lines.append(
            f"[{item['priority']}] {item['title']}  "
            f"(severity: {item['highest_severity']}, "
            f"assets: {len(item['affected_assets'])})"
        )
        for step in item["steps"]:
            for ln in step.splitlines():
                lines.append(f"    - {ln}" if ln is step.splitlines()[0] else f"      {ln}")
        lines.append("")
    return "\n".join(lines)
