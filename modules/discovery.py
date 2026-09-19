"""
discovery.py - Network scan + device inventory
Built by MR CYBER (Harsh Saini)
"""
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


def lookup_vendor(mac, oui_db):
    mac_prefix = mac.upper().replace("-", ":")[:8]
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


def scan_ports(ip, ports=(21, 22, 23, 80, 443, 1883, 8080), timeout=0.5):
    """Real TCP connect scan on a short common-port list."""
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except OSError:
            continue
    return open_ports


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
