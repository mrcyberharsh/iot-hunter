"""Conservative service fingerprinting for authorized local device inventory."""
import logging
import re
import socket

import requests

logger = logging.getLogger("iothunter.fingerprint")
DEVICE_HINTS = {
    "camera": ["ipcam", "dahua", "hikvision", "camera", "rtsp"],
    "router": ["router", "gateway", "openwrt", "dd-wrt", "tp-link", "netgear"],
    "bulb": ["yeelight", "lifx", "tuya", "shelly"],
    "sensor": ["sensor", "esp32", "esp8266", "arduino"],
}


def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((ip, port))
            if port in (80, 8080):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            return sock.recv(1024).decode(errors="ignore").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def classify_device(banner_text, vendor=""):
    text = (banner_text or "").lower() + " " + (vendor or "").lower()
    for kind, keywords in DEVICE_HINTS.items():
        if any(word in text for word in keywords):
            return kind
    return "unknown"


def parse_banner_service(banner):
    if not banner:
        return "unknown", None
    text = banner.strip()
    patterns = [
        ("apache", ["apache"]), ("nginx", ["nginx"]), ("ssh", ["ssh"]),
        ("telnet", ["telnet"]), ("mqtt", ["mqtt"]), ("http", ["http"]),
        ("ftp", ["ftp"]), ("smtp", ["smtp"]), ("mysql", ["mysql"]),
        ("redis", ["redis"]), ("postgresql", ["postgres", "postgresql"]),
        ("mongodb", ["mongodb"]),
    ]
    for service, keywords in patterns:
        for keyword in keywords:
            if keyword in text.lower():
                match = re.search(rf"{re.escape(keyword)}[ /:-]*v?([0-9]+(?:\.[0-9]+){{0,3}})", text, re.I)
                return service, match.group(1) if match else None
    return "unknown", None


def query_nvd_cves(service_name, version=None, results_per_page=5):
    """Look up public vulnerability references; results require manual validation."""
    if not service_name or service_name == "unknown":
        return []
    query = service_name if version is None else f"{service_name} {version}"
    try:
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": query, "resultsPerPage": str(min(max(1, results_per_page), 10))},
            timeout=8,
        )
        response.raise_for_status()
        payload = response.json()
        return [{
            "id": item.get("cve", {}).get("id"),
            "description": (item.get("cve", {}).get("descriptions") or [{}])[0].get("value", "No description available"),
            "published": item.get("cve", {}).get("published"),
        } for item in payload.get("vulnerabilities", [])[:results_per_page]]
    except (requests.RequestException, ValueError, TypeError) as exc:
        logger.warning("NVD lookup failed for %s: %s", query, exc)
        return []


def fingerprint_device(device):
    banners = {}
    for port in device.get("open_ports", []):
        banner = grab_banner(device["ip"], int(port))
        if banner:
            banners[int(port)] = banner
    device_type = classify_device(" ".join(banners.values()), device.get("vendor", ""))
    cves = []
    for port, banner in banners.items():
        service, version = parse_banner_service(banner)
        references = query_nvd_cves(service, version)
        if service != "unknown":
            cves.append({"port": port, "service": service, "version": version, "cves": references})
    result = dict(device)
    result.update({"banners": banners, "device_type": device_type, "cves": cves})
    return result


def run_fingerprint(devices):
    return [fingerprint_device(device) for device in devices]
