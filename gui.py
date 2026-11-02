"""
fingerprint.py - Real banner grabbing and device-type detection
Built by MR CYBER (Harsh Saini)
"""
import logging
import re
import socket

import requests

from modules.discovery import lookup_vendor

logger = logging.getLogger("iothunter.fingerprint")

try:
    import manuf
    MANUF_DB = manuf.MACdb()
except Exception:  # pragma: no cover
    MANUF_DB = None

DEVICE_HINTS = {
    "camera": ["ipcam", "dahua", "hikvision", "camera", "rtsp"],
    "router": ["router", "gateway", "openwrt", "dd-wrt", "tp-link", "netgear"],
    "bulb": ["yeelight", "lifx", "tuya", "shelly"],
    "sensor": ["sensor", "esp32", "esp8266", "arduino"],
}


def grab_banner(ip, port, timeout=2):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port == 80 or port == 8080:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore")
            return banner.strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def classify_device(banner_text, vendor=""):
    text = (banner_text or "").lower() + " " + (vendor or "").lower()
    for device_type, keywords in DEVICE_HINTS.items():
        if any(k in text for k in keywords):
            return device_type
    return "unknown"


def parse_banner_service(banner):
    if not banner:
        return "unknown", None

    text = banner.strip()
    service_patterns = [
        ("apache", ["apache"]),
        ("nginx", ["nginx"]),
        ("ssh", ["ssh"]),
        ("telnet", ["telnet"]),
        ("openssl", ["openssl"]),
        ("mqtt", ["mqtt"]),
        ("http", ["http"]),
        ("ftp", ["ftp"]),
        ("smtp", ["smtp"]),
        ("mysql", ["mysql"]),
        ("redis", ["redis"]),
        ("postgresql", ["postgres", "postgresql"]),
        ("mongodb", ["mongodb"]),
        ("miniupnpd", ["miniupnpd"]),
    ]

    for service_name, keywords in service_patterns:
        for keyword in keywords:
            if keyword.lower() in text.lower():
                match = re.search(rf"{re.escape(keyword)}[ /:-]*v?([0-9]+(?:\.[0-9]+){{0,3}})", text, re.I)
                version = match.group(1) if match else None
                return service_name, version
    return "unknown", None


def query_nvd_cves(service_name, version=None, results_per_page=5):
    if not service_name or service_name == "unknown":
        return []

    query = service_name if version is None else f"{service_name} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": str(results_per_page)}

    try:
        response = requests.get(url, params=params, timeout=8)
        response.raise_for_status()
        payload = response.json()
        vulns = payload.get("vulnerabilities", [])
        results = []
        for item in vulns[:results_per_page]:
            cve = item.get("cve", {})
            results.append({
                "id": cve.get("id"),
                "description": (cve.get("descriptions", [{}])[0].get("value") if cve.get("descriptions") else "No description available"),
                "published": cve.get("published"),
            })
        return results
    except Exception as exc:  # pragma: no cover
        logger.warning("NVD lookup failed for %s: %s", query, exc)
        return []


def banner_cve_summary(port, banner):
    service_name, version = parse_banner_service(banner)
    cves = query_nvd_cves(service_name, version)
    return {
        "port": port,
        "service": service_name,
        "version": version,
        "cves": cves,
    }


def fingerprint_device(device):
    """device: dict with ip, mac, vendor, open_ports"""
    banners = {}
    for port in device.get("open_ports", []):
        banner = grab_banner(device["ip"], port)
        if banner:
            banners[port] = banner

    combined = " ".join(banners.values())
    device_type = classify_device(combined, device.get("vendor", ""))

    cve_findings = []
    for port, banner in banners.items():
        hit = banner_cve_summary(port, banner)
        if hit["cves"] or hit["service"] != "unknown":
            cve_findings.append(hit)

    result = dict(device)
    result["banners"] = banners
    result["device_type"] = device_type
    result["cves"] = cve_findings
    logger.info("Fingerprinted %s as %s", device["ip"], device_type)
    return result


def run_fingerprint(devices):
    return [fingerprint_device(d) for d in devices]


__all__ = [
    "grab_banner",
    "classify_device",
    "parse_banner_service",
    "query_nvd_cves",
    "banner_cve_summary",
    "fingerprint_device",
    "run_fingerprint",
]

