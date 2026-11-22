"""
protocol.py - Insecure protocol detection via live capture
Built by MR CYBER (Harsh Saini)
"""
import re
import logging

logger = logging.getLogger("iothunter.protocol")

try:
    from scapy.all import sniff, TCP, Raw, IP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

INSECURE_PORTS = {
    21: ("FTP", "high"),
    23: ("Telnet", "high"),
    80: ("HTTP", "medium"),
    1883: ("MQTT (unencrypted)", "medium"),
}

CRED_PATTERNS = [
    re.compile(rb"user\w*[:=]\s*\S+", re.I),
    re.compile(rb"pass\w*[:=]\s*\S+", re.I),
    re.compile(rb"Authorization: Basic", re.I),
]


def detect_plaintext_creds(payload):
    for pattern in CRED_PATTERNS:
        if pattern.search(payload):
            return True
    return False


def run_protocol_scan(duration_sec=30):
    if not SCAPY_OK:
        raise RuntimeError("scapy is required for protocol detection. Install with: pip install scapy")

    findings = []
    seen = set()

    def handle_packet(pkt):
        if TCP not in pkt or IP not in pkt:
            return
        port = pkt[TCP].dport
        if port not in INSECURE_PORTS:
            port = pkt[TCP].sport
        if port not in INSECURE_PORTS:
            return

        proto_name, risk = INSECURE_PORTS[port]
        key = (pkt[IP].src, pkt[IP].dst, port)
        cred_leak = False
        if Raw in pkt:
            cred_leak = detect_plaintext_creds(bytes(pkt[Raw].load))

        if key not in seen:
            seen.add(key)
            findings.append({
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "port": port,
                "protocol": proto_name,
                "risk": risk,
                "plaintext_creds_seen": cred_leak,
            })
            logger.info("Insecure protocol observed: %s -> %s on %s", pkt[IP].src, pkt[IP].dst, proto_name)
        elif cred_leak:
            for f in findings:
                if f["src"] == pkt[IP].src and f["dst"] == pkt[IP].dst and f["port"] == port:
                    f["plaintext_creds_seen"] = True

    print(f"[*] Scanning for insecure protocols over {duration_sec}s of live traffic...")
    sniff(prn=handle_packet, timeout=duration_sec, store=False)

    return findings
