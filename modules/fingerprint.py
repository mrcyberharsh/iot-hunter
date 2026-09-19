"""
fingerprint.py - Real banner grabbing and device-type detection
Built by MR CYBER (Harsh Saini)
"""
import socket
import logging

logger = logging.getLogger("iothunter.fingerprint")

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


def fingerprint_device(device):
    """device: dict with ip, mac, vendor, open_ports"""
    banners = {}
    for port in device.get("open_ports", []):
        banner = grab_banner(device["ip"], port)
        if banner:
            banners[port] = banner

    combined = " ".join(banners.values())
    device_type = classify_device(combined, device.get("vendor", ""))

    result = dict(device)
    result["banners"] = banners
    result["device_type"] = device_type
    logger.info("Fingerprinted %s as %s", device["ip"], device_type)
    return result


def run_fingerprint(devices):
    return [fingerprint_device(d) for d in devices]
