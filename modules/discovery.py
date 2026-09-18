"""Network discovery: ARP sweep + nmap port scan + offline OUI vendor lookup."""
from __future__ import annotations

import csv
import ipaddress
import logging
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional, Tuple

from .models import Finding
from .utils import normalize_mac

log = logging.getLogger(__name__)

try:
    from scapy.all import ARP, Ether, srp, conf as scapy_conf  # type: ignore
    SCAPY_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    SCAPY_AVAILABLE = False
    log.error("scapy unavailable: %s", exc)

try:
    import nmap  # type: ignore  # python-nmap
    NMAP_AVAILABLE = True
except Exception as exc:  # pragma: no cover
    NMAP_AVAILABLE = False
    log.error("python-nmap unavailable: %s", exc)


# --------------------------------------------------------------------------- #
# Ports worth flagging at discovery time
# --------------------------------------------------------------------------- #
RISKY_PORTS: Dict[int, Tuple[str, str, str]] = {
    21:    ("FTP service exposed", "high",
            "FTP transmits credentials and data in cleartext."),
    23:    ("Telnet service exposed", "critical",
            "Telnet transmits all data including credentials in cleartext."),
    2323:  ("Telnet (alternate port) exposed", "critical",
            "Telnet on a non-standard port is still cleartext."),
    445:   ("SMB service exposed", "high",
            "SMB exposure enables lateral movement and ransomware."),
    1883:  ("MQTT broker exposed (plaintext)", "high",
            "MQTT on 1883 has no transport encryption."),
    1900:  ("UPnP/SSDP service exposed", "medium",
            "UPnP enables unauthenticated device control and NAT traversal."),
    3389:  ("RDP service exposed", "high",
            "Exposed RDP is a common initial-access vector."),
    5900:  ("VNC service exposed", "high",
            "VNC frequently runs without authentication or with weak passwords."),
    80:    ("Unencrypted HTTP management interface", "medium",
            "Management UI reachable over plaintext HTTP."),
    8080:  ("Unencrypted HTTP management interface (alt)", "medium",
            "Management UI reachable over plaintext HTTP."),
    554:   ("RTSP stream exposed", "medium",
            "RTSP streams frequently lack authentication."),
    6668:  ("IRC service exposed", "high",
            "IRC on an IoT device commonly indicates a botnet client."),
    22:    ("SSH service exposed", "low",
            "Ensure key-based auth and disable password logins."),
}


# --------------------------------------------------------------------------- #
# Offline OUI database
# --------------------------------------------------------------------------- #
class OUIDatabase:
    """Offline IEEE OUI lookup. CSV format: `prefix,vendor`."""

    def __init__(self, path: str):
        self.path = path
        self.prefixes: Dict[str, str] = {}
        if path and os.path.isfile(path):
            self._load(path)
            log.info("Loaded %d OUI prefixes from %s", len(self.prefixes), path)
        else:
            log.warning("OUI database not found at %s — vendor lookup disabled", path)

    def _load(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.reader(fh):
                if not row or len(row) < 2:
                    continue
                raw = row[0].strip().strip('"')
                vendor = row[1].strip().strip('"')
                if not raw or raw.startswith("#"):
                    continue
                key = (
                    raw.replace(":", "").replace("-", "").replace(".", "").upper()
                )
                if len(key) >= 6:
                    self.prefixes[key[:6]] = vendor

    def lookup(self, mac: str) -> str:
        if not mac:
            return "Unknown"
        key = (
            mac.replace(":", "").replace("-", "").replace(".", "").upper()[:6]
        )
        return self.prefixes.get(key, "Unknown")


# --------------------------------------------------------------------------- #
# Low-level scanners
# --------------------------------------------------------------------------- #
def arp_sweep(
    interface: str, network: ipaddress.IPv4Network, timeout: float, retries: int
) -> Dict[str, str]:
    """Return {ip: mac} for live hosts, using ARP requests."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for ARP discovery (pip install scapy)")

    scapy_conf.iface = interface
    scapy_conf.verb = 0

    hosts: Dict[str, str] = {}
    for attempt in range(1, max(1, retries) + 1):
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
        try:
            answered, _ = srp(
                pkt, iface=interface, timeout=timeout, verbose=False, retry=0
            )
        except PermissionError as exc:
            raise RuntimeError(
                "ARP sweep requires root / CAP_NET_RAW privileges"
            ) from exc
        for _, rcv in answered:
            hosts[rcv.psrc] = normalize_mac(rcv.hwsrc)
        if hosts:
            break
        log.debug("ARP sweep attempt %d returned no hosts", attempt)
    return hosts


def nmap_port_scan(
    network: ipaddress.IPv4Network, arguments: str
) -> Dict[str, Dict[str, Any]]:
    """Run an nmap scan over the subnet and return per-host open ports."""
    if not NMAP_AVAILABLE:
        raise RuntimeError("python-nmap is required (pip install python-nmap)")

    scanner = nmap.PortScanner()
    log.info("nmap %s -> %s", arguments, network)
    scanner.scan(hosts=str(network), arguments=arguments)

    results: Dict[str, Dict[str, Any]] = {}
    for host in scanner.all_hosts():
        entry = scanner[host]
        ports: List[Dict[str, Any]] = []
        for proto in ("tcp", "udp"):
            if proto not in entry:
                continue
            for port, data in entry[proto].items():
                if data.get("state") != "open":
                    continue
                ports.append(
                    {
                        "port": int(port),
                        "proto": proto,
                        "service": data.get("name", "") or "",
                        "product": data.get("product", "") or "",
                        "version": data.get("version", "") or "",
                        "extrainfo": data.get("extrainfo", "") or "",
                    }
                )
        ports.sort(key=lambda p: p["port"])
        results[host] = {
            "hostname": entry.hostname() or "",
            "state": entry.state(),
            "ports": ports,
        }
    return results


_DNS_POOL = ThreadPoolExecutor(max_workers=16, thread_name_prefix="dns")


def reverse_dns(ip: str, timeout: float = 2.0) -> str:
    """Best-effort reverse DNS with a hard timeout."""
    try:
        fut = _DNS_POOL.submit(socket.gethostbyaddr, ip)
        return fut.result(timeout=timeout)[0]
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Discovery orchestrator
# --------------------------------------------------------------------------- #
class Discovery:
    def __init__(self, config: Dict[str, Any], oui: OUIDatabase):
        self.config = config
        self.scan_cfg = config.get("scan", {}) or {}
        self.oui = oui

    def run(
        self, interface: str, network: ipaddress.IPv4Network
    ) -> Tuple[List[Dict[str, Any]], List[Finding]]:
        findings: List[Finding] = []
        devices: List[Dict[str, Any]] = []

        # --- 1. ARP sweep ---------------------------------------------------
        log.info("Starting ARP sweep on %s (%s)", network, interface)
        arp_hosts = arp_sweep(
            interface,
            network,
            float(self.scan_cfg.get("arp_timeout", 3)),
            int(self.scan_cfg.get("arp_retries", 2)),
        )
        log.info("ARP sweep found %d live host(s)", len(arp_hosts))

        # --- 2. nmap port scan ---------------------------------------------
        nmap_results: Dict[str, Dict[str, Any]] = {}
        args = self.scan_cfg.get(
            "nmap_arguments", "-sV -T4 --top-ports 200 --host-timeout 90s"
        )
        try:
            nmap_results = nmap_port_scan(network, args)
        except Exception as exc:
            log.error("nmap scan failed: %s", exc)
            findings.append(
                Finding(
                    id="disc-nmap-failed",
                    title="Port scan could not be completed",
                    severity="info",
                    category="scan_error",
                    description=f"nmap scan failed: {exc}",
                    remediation="Ensure nmap is installed and the process has sufficient privileges.",
                )
            )

        # --- 3. Merge + enrich ---------------------------------------------
        all_ips = sorted(set(arp_hosts) | set(nmap_results), key=_ip_sort_key)
        dns_timeout = float(self.scan_cfg.get("dns_timeout", 2.0))

        for ip in all_ips:
            mac = arp_hosts.get(ip, "")
            vendor = self.oui.lookup(mac) if mac else "Unknown"
            nm = nmap_results.get(ip, {})
            hostname = nm.get("hostname") or reverse_dns(ip, dns_timeout)
            ports = nm.get("ports", [])

            device = {
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "hostname": hostname,
                "ports": ports,
                "state": nm.get("state", "up"),
            }
            devices.append(device)

            # Findings for risky exposed ports
            for p in ports:
                pnum = p["port"]
                if pnum in RISKY_PORTS:
                    title, sev, desc = RISKY_PORTS[pnum]
                    findings.append(
                        Finding(
                            id=f"port-{ip}-{pnum}",
                            title=title,
                            severity=sev,
                            category="exposed_service",
                            description=f"{desc} (port {pnum}/{p['proto']} on {ip}).",
                            asset=ip,
                            evidence={
                                "port": pnum,
                                "proto": p["proto"],
                                "service": p.get("service", ""),
                                "product": p.get("product", ""),
                                "version": p.get("version", ""),
                                "mac": mac,
                                "vendor": vendor,
                            },
                        )
                    )

            # ARP-only hosts (no ports found) still get inventoried
            if not ports and mac:
                log.debug("Host %s answered ARP but had no open scanned ports", ip)

        return devices, findings


def _ip_sort_key(ip: str):
    try:
        return (0, int(ipaddress.IPv4Address(ip)))
    except ValueError:
        return (1, ip)
