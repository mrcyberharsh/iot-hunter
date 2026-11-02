"""
discovery.py - Network scan + device inventory
Built by MR CYBER (Harsh Saini)
"""
import asyncio
import socket
import psutil
import ipaddress
import logging

logger = logging.getLogger("iothunter.discovery")

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import manuf
    MANUF_DB = manuf.MACdb()
except Exception:  # pragma: no cover
    MANUF_DB = None


def get_active_interface():
    """Auto-detect an interface that is UP and has an IPv4 address."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for name, st in stats.items():
        if not st.isup:
            continue
        for addr in addrs.get(name, []):
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                return name, addr.address, addr.netmask
    return None, None, None


def get_subnet(ip, netmask):
    net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(net)


def load_oui_db(path):
    db = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                prefix, vendor = line.split(" ", 1)
                prefix = prefix.replace("*", "").rstrip(":").upper()
                db[prefix] = vendor.strip()
    except FileNotFoundError:
        logger.warning("OUI database not found at %s", path)
    return db


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

    normalized = mac.upper().replace("-", ":")
    mac_prefix = normalized[:8]
    if oui_db:
        for prefix, vendor in oui_db.items():
            if mac_prefix.startswith(prefix[:8]):
                return vendor
    return "Unknown"


def arp_scan(subnet, timeout=3):
    """Perform a real ARP scan of the given subnet. Returns list of dicts."""
    if not SCAPY_OK:
        raise RuntimeError("scapy is required for ARP scanning. Install with: pip install scapy")

    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=timeout, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc,
        })
    return devices


async def async_scan_port(ip, port, timeout=0.5):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError, ConnectionRefusedError, ValueError):
        return False


async def async_scan_ports(ip, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    """Async TCP connect scan on a short common-port list."""
    tasks = [async_scan_port(ip, port, timeout) for port in ports]
    results = await asyncio.gather(*tasks)
    return [port for port, is_open in zip(ports, results) if is_open]


def scan_ports(ip, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    """Sync wrapper for async port scan."""
    return asyncio.run(async_scan_ports(ip, ports, timeout))


async def async_scan_network(subnet, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    """Scan an arbitrary CIDR block asynchronously and return active IPs with open ports."""
    network = ipaddress.ip_network(subnet, strict=False)
    if network.num_addresses > 256:
        hosts = [str(ip) for ip in network.hosts()][:256]
    else:
        hosts = [str(ip) for ip in network.hosts()]

    results = []
    for host_ip in hosts:
        open_ports = await async_scan_ports(host_ip, ports, timeout)
        if open_ports:
            results.append({"ip": host_ip, "open_ports": open_ports})
    return results


def scan_target_network(subnet, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    """Sync wrapper to scan a target subnet range such as 192.168.1.0/24."""
    return asyncio.run(async_scan_network(subnet, ports, timeout))


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
    print("[*] Running ARP scan (real, no simulated data)...")

    hosts = arp_scan(subnet)
    inventory = []
    for h in hosts:
        vendor = lookup_vendor(h["mac"], oui_db)
        ports = scan_ports(h["ip"])
        hostname = resolve_hostname(h["ip"])
        entry = {
            "ip": h["ip"],
            "mac": h["mac"],
            "vendor": vendor,
            "hostname": hostname or "N/A",
            "open_ports": ports,
        }
        inventory.append(entry)
        logger.info("Discovered device: %s", entry)

    return {"interface": iface, "subnet": subnet, "devices": inventory}


__all__ = [
    "get_active_interface",
    "get_subnet",
    "load_oui_db",
    "lookup_vendor",
    "arp_scan",
    "scan_ports",
    "async_scan_ports",
    "async_scan_network",
    "scan_target_network",
    "resolve_hostname",
    "run_discovery",
]

