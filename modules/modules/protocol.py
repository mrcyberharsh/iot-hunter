"""Passive detection of insecure / cleartext protocols and credentials."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set

from .models import Finding

log = logging.getLogger(__name__)

try:
    from scapy.all import IP, TCP, UDP, Raw, sniff, conf as scapy_conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover
    SCAPY_AVAILABLE = False


# port -> (protocol name, severity, description)
INSECURE_PORTS = {
    21:   ("FTP", "high", "FTP transmits credentials and files in cleartext."),
    23:   ("Telnet", "critical", "Telnet transmits all data, including credentials, in cleartext."),
    2323: ("Telnet (alt)", "critical", "Telnet on a non-standard port is still cleartext."),
    80:   ("HTTP", "medium", "Plaintext HTTP management traffic."),
    8080: ("HTTP (alt)", "medium", "Plaintext HTTP management traffic."),
    8000: ("HTTP (alt)", "medium", "Plaintext HTTP management traffic."),
    1883: ("MQTT (plaintext)", "high", "MQTT without TLS exposes payloads and credentials."),
    143:  ("IMAP (plaintext)", "high", "IMAP without TLS exposes credentials."),
    110:  ("POP3", "high", "POP3 without TLS exposes credentials."),
    25:   ("SMTP (plaintext)", "medium", "SMTP without TLS exposes message content."),
    161:  ("SNMPv1/v2c", "high", "SNMPv1/v2c community strings are sent in cleartext."),
    1900: ("SSDP/UPnP", "medium", "UPnP has no authentication."),
}

# Regular expressions for credential leakage
_CRED_PATTERNS = [
    ("FTP USER", re.compile(rb"^USER\s+(\S+)", re.M)),
    ("FTP PASS", re.compile(rb"^PASS\s+(\S+)", re.M)),
    ("POP3 USER", re.compile(rb"^USER\s+(\S+)", re.M)),
    ("POP3 PASS", re.compile(rb"^PASS\s+(\S+)", re.M)),
    ("IMAP LOGIN", re.compile(rb"^[A-Z0-9]+\s+LOGIN\s+(\S+)\s+(\S+)", re.M | re.I)),
    ("HTTP Basic", re.compile(rb"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", re.I)),
    ("HTTP Form", re.compile(rb"(?:username|user|login)=([^&\s]+)&(?:password|pass|pwd)=([^&\s]+)", re.I)),
    ("Telnet login", re.compile(rb"login:\s*(\S+)", re.I)),
]


def _decode_b64(value: bytes) -> Optional[str]:
    try:
        return base64.b64decode(value + b"=" * (-len(value) % 4)).decode(
            "utf-8", errors="replace"
        )
    except (binascii.Error, ValueError):
        return None


def _extract_credentials(payload: bytes) -> List[Dict[str, str]]:
    hits: List[Dict[str, str]] = []
    for label, rx in _CRED_PATTERNS:
        for m in rx.finditer(payload):
            groups = [g.decode("utf-8", "replace") for g in m.groups() if g]
            if label == "HTTP Basic":
                decoded = _decode_b64(m.group(1))
                if decoded:
                    hits.append({"type": label, "value": decoded})
            elif groups:
                hits.append({"type": label, "value": ":".join(groups)})
    return hits


class ProtocolAnalyzer:
    """Analyse captured packets for cleartext protocols & leaked credentials."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.findings: List[Finding] = []
        self._seen_ports: Set[tuple] = set()
        self._seen_creds: Set[str] = set()

    # ------------------------------------------------------------------ #
    def analyze_packets(self, packets) -> List[Finding]:
        for pkt in packets:
            self._analyze_one(pkt)
        return list(self.findings)

    def _analyze_one(self, pkt) -> None:
        if IP not in pkt:
            return
        ip = pkt[IP]
        src, dst = ip.src, ip.dst

        l4 = "tcp" if TCP in pkt else "udp" if UDP in pkt else None
        if l4 is None:
            return
        layer = pkt[TCP] if l4 == "tcp" else pkt[UDP]
        sport, dport = int(layer.sport), int(layer.dport)

        # --- insecure protocol by port --------------------------------- #
        for port, (name, sev, desc) in INSECURE_PORTS.items():
            if dport == port or sport == port:
                key = (name, src, dst, port)
                if key in self._seen_ports:
                    continue
                self._seen_ports.add(key)
                direction = f"{src} -> {dst}" if dport == port else f"{dst} -> {src}"
                self.findings.append(
                    Finding(
                        id=f"proto-{name.replace(' ', '_')}-{src}-{dst}-{port}",
                        title=f"Insecure protocol in use: {name}",
                        severity=sev,
                        category="insecure_protocol",
                        description=f"{desc} Observed on {direction}:{port}.",
                        asset=src if dport == port else dst,
                        evidence={
                            "protocol": name,
                            "port": port,
                            "source": src,
                            "destination": dst,
                        },
                    )
                )

        # --- plaintext credentials ------------------------------------- #
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if not payload:
                return
            hits = _extract_credentials(payload)
            for hit in hits:
                sig = f"{src}:{dst}:{hit['type']}:{hit['value']}"
                if sig in self._seen_creds:
                    continue
                self._seen_creds.add(sig)
                # Redact the secret portion in the report
                value = hit["value"]
                if ":" in value:
                    user, _, secret = value.partition(":")
                    shown = f"{user}:{'*' * max(3, len(secret))}"
                else:
                    shown = "*" * max(3, len(value))

                self.findings.append(
                    Finding(
                        id=f"cleartext-cred-{hash(sig) & 0xFFFFFFFF:08x}",
                        title="Cleartext credentials observed in transit",
                        severity="critical",
                        category="plaintext_credentials",
                        description=(
                            f"Credentials were transmitted in cleartext between {src} "
                            f"and {dst} ({hit['type']}). Value: {shown}"
                        ),
                        asset=src,
                        evidence={
                            "source": src,
                            "destination": dst,
                            "type": hit["type"],
                            "redacted_value": shown,
                        },
                    )
                )

    # ------------------------------------------------------------------ #
    def capture(
        self, interface: str, duration_seconds: int, bpf: str = "ip"
    ) -> List[Finding]:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for protocol analysis")
        scapy_conf.iface = interface
        log.info("Passive protocol capture on %s for %ds", interface, duration_seconds)
        packets = sniff(
            iface=interface, filter=bpf, timeout=duration_seconds, store=True
        )
        log.info("Captured %d packet(s) for protocol analysis", len(packets))
        return self.analyze_packets(packets)

    def analyze_pcap(self, path: str) -> List[Finding]:
        if not SCAPY_AVAILABLE:
            raise RuntimeError("scapy is required for pcap analysis")
        from scapy.all import rdpcap  # type: ignore
        packets = rdpcap(path)
        return self.analyze_packets(packets)
