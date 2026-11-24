#!/usr/bin/env python3
"""Local network discovery for explicitly authorized IoT inventories."""
import asyncio
import ipaddress
import logging
import math
import socket

import psutil

logger = logging.getLogger("iothunter.discovery")
MAX_CONCURRENT_PORT_CHECKS = 32
try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False
try:
    import manuf
    MANUF_DB = manuf.MACdb()
except Exception:
    MANUF_DB = None


def get_active_interface():
    """Return the first active non-loopback IPv4 interface."""
    for name, status in psutil.net_if_stats().items():
        if not status.isup:
            continue
        for address in psutil.net_if_addrs().get(name, []):
            if address.family == socket.AF_INET and not address.address.startswith("127."):
                return name, address.address, address.netmask
    return None, None, None


def get_subnet(ip, netmask):
    return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))


def load_oui_db(path):
    db = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or " " not in line:
                    continue
                prefix, vendor = line.split(" ", 1)
                db[prefix.replace("*", "").rstrip(":").upper()] = vendor.strip()
    except FileNotFoundError:
        logger.warning("OUI database not found at %s", path)
    return db


def _validate_scan_network(subnet, message):
    network = ipaddress.ip_network(subnet, strict=False)
    if (
        not isinstance(network, ipaddress.IPv4Network)
        or not network.is_private
        or network.is_multicast
        or network.is_loopback
        or network.num_addresses > 256
    ):
        raise ValueError(message)
    return network


def lookup_vendor(mac, oui_db=None):
    if not mac:
        return "Unknown"
    if MANUF_DB is not None:
        try:
            vendor = MANUF_DB.get_vendor(mac)
            if vendor and vendor != "Unknown":
                return vendor
        except Exception:
            pass
    prefix = mac.upper().replace("-", ":")[:8]
    for key, vendor in (oui_db or {}).items():
        if prefix.startswith(key[:8]):
            return vendor
    return "Unknown"


def arp_scan(subnet, timeout=3):
    """Discover hosts with ARP on a local, authorized subnet."""
    network = _validate_scan_network(
        subnet,
        "ARP discovery is limited to private IPv4 networks with at most 256 addresses.",
    )
    if not SCAPY_OK:
        raise RuntimeError("scapy is required for ARP scanning. Install the project requirements.")
    answered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
                   timeout=timeout, verbose=False)[0]
    return [{"ip": received.psrc, "mac": received.hwsrc} for _, received in answered]


async def async_scan_port(ip, port, timeout=0.5):
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Port scan timeout must be greater than zero.")
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, OSError, ValueError):
        return False
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except (asyncio.TimeoutError, OSError):
        pass
    return True


async def async_scan_ports(ip, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_PORT_CHECKS)

    async def bounded_scan(port):
        async with semaphore:
            return await async_scan_port(ip, port, timeout)

    checks = await asyncio.gather(*(bounded_scan(port) for port in ports))
    return [port for port, opened in zip(ports, checks) if opened]


def _run_async(coroutine):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise RuntimeError(
        "Synchronous scan helpers cannot run inside an event loop; "
        "use the corresponding async_scan_* function."
    )


def scan_ports(ip, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    return _run_async(async_scan_ports(ip, ports, timeout))


async def async_scan_network(subnet, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    network = _validate_scan_network(
        subnet,
        "Explicit network inventory is limited to private IPv4 ranges with at most 256 addresses.",
    )
    results = []
    for host in network.hosts():
        host_ip = str(host)
        opened = await async_scan_ports(host_ip, ports, timeout)
        if opened:
            results.append({"ip": host_ip, "open_ports": opened})
    return results


def scan_target_network(subnet, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    return _run_async(async_scan_network(subnet, ports, timeout))


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def run_discovery(config):
    iface, ip, netmask = get_active_interface()
    if not ip:
        raise RuntimeError("No active network interface with an IPv4 address found.")
    subnet = get_subnet(ip, netmask)
    oui_db = load_oui_db(config.get("oui_db_path", "modules/data/oui.txt"))
    print(f"[*] Interface: {iface}  IP: {ip}  Subnet: {subnet}")
    print("[*] Running ARP discovery on the active local subnet...")
    inventory = []
    for host in arp_scan(subnet):
        ports = scan_ports(host["ip"])
        entry = {
            "ip": host["ip"], "mac": host["mac"],
            "vendor": lookup_vendor(host["mac"], oui_db),
            "hostname": resolve_hostname(host["ip"]) or "N/A",
            "open_ports": ports,
        }
        inventory.append(entry)
        logger.info("Discovered device: %s", entry)
    return {"interface": iface, "subnet": subnet, "devices": inventory}


__all__ = ["get_active_interface", "get_subnet", "load_oui_db", "lookup_vendor",
           "arp_scan", "scan_ports", "async_scan_ports", "async_scan_network",
           "scan_target_network", "resolve_hostname", "run_discovery"]
