"""Device fingerprinting: banners, HTTP headers, protocol probes, type inference."""
from __future__ import annotations

import http.client
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional

from .models import Finding

log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Banner grabbing
# --------------------------------------------------------------------------- #
_HTTP_PORTS = {80, 81, 88, 8000, 8008, 8080, 8081, 8888}
_TLS_PORTS = {443, 8443, 9443}
_NUDGE = {
    21: b"\r\n",
    22: b"",
    23: b"\r\n",
    25: b"EHLO iot-hunter\r\n",
    110: b"\r\n",
    143: b"\r\n",
    554: b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n",
    1883: b"",
    6667: b"\r\n",
}


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Connect and read whatever the service offers (with a small nudge)."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            nudge = _NUDGE.get(port)
            if nudge is None and port in _HTTP_PORTS:
                nudge = (
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: iot-hunter\r\n\r\n"
                ).encode()
            if nudge:
                try:
                    sock.sendall(nudge)
                except OSError:
                    pass
            chunks = []
            while True:
                try:
                    data = sock.recv(2048)
                except socket.timeout:
                    break
                if not data:
                    break
                chunks.append(data)
                if sum(len(c) for c in chunks) > 8192:
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")
    except (OSError, ssl.SSLError):
        return ""


def http_headers(ip: str, port: int, timeout: float, use_tls: bool) -> Dict[str, str]:
    """Fetch HTTP response headers from a device."""
    try:
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("HEAD", "/", headers={"User-Agent": "iot-hunter"})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        headers["_status"] = str(resp.status)
        conn.close()
        return headers
    except Exception:
        return {}


def mqtt_probe(ip: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    """Send an MQTT CONNECT and inspect the CONNACK."""
    def _str(s: str) -> bytes:
        b = s.encode()
        return len(b).to_bytes(2, "big") + b

    def _remaining_length(n: int) -> bytes:
        out = bytearray()
        while True:
            digit = n % 128
            n //= 128
            if n > 0:
                digit |= 0x80
            out.append(digit)
            if n == 0:
                break
        return bytes(out)

    try:
        client_id = "iot-hunter-probe"
        flags = 0x02  # clean session
        payload = _str(client_id)
        variable = _str("MQTT") + bytes([4, flags]) + (30).to_bytes(2, "big")
        body = variable + payload
        packet = b"\x10" + _remaining_length(len(body)) + body

        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            resp = sock.recv(8)
        if len(resp) >= 4 and resp[0] == 0x20:
            return {"connack_rc": resp[3], "anonymous_allowed": resp[3] == 0x00}
    except Exception:
        return None
    return None


def coap_probe(ip: str, port: int, timeout: float) -> Optional[str]:
    """Send a CoAP GET /.well-known/core and return the payload text."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            # Ver=1, Type=CON, TKL=0, Code=0.01 GET, MID=0x0001
            pkt = bytes([0x40, 0x01, 0x00, 0x01]) + b"\xbb.well-known\x04core"
            sock.sendto(pkt, (ip, port))
            data, _ = sock.recvfrom(2048)
            return data[4:].decode("utf-8", errors="replace")
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Device type inference
# --------------------------------------------------------------------------- #
_VENDOR_HINTS = [
    (re.compile(r"hikvision|dahua|axis|amcrest|reolink|foscam|wyze", re.I), "IP Camera"),
    (re.compile(r"philips|signify|hue|lifx|lutron", re.I), "Smart Lighting"),
    (re.compile(r"nest|ecobee|honeywell|tado", re.I), "Thermostat"),
    (re.compile(r"sonos|roku|chromecast|amazon|echo|firetv", re.I), "Smart Speaker / Media"),
    (re.compile(r"raspberry", re.I), "Single-Board Computer"),
    (re.compile(r"espressif|esp32|esp8266|tuya|shelly|sonoff", re.I), "Embedded IoT Module"),
    (re.compile(r"tp-link|netgear|d-link|asus|ubiquiti|mikrotik|cisco|aruba", re.I), "Router / AP"),
    (re.compile(r"withings|fitbit|garmin", re.I), "Wearable"),
]

_BANNER_HINTS = [
    (re.compile(r"rtsp|h264|h265|mjpeg", re.I), "IP Camera"),
    (re.compile(r"mqtt", re.I), "MQTT Device"),
    (re.compile(r"coap", re.I), "CoAP Sensor"),
    (re.compile(r"router|gateway|openwrt|dd-wrt|routeros", re.I), "Router / AP"),
    (re.compile(r"printer|cups|lpd", re.I), "Printer"),
    (re.compile(r"nas|synology|qnap|freenas", re.I), "NAS"),
    (re.compile(r"busybox", re.I), "Embedded Linux Device"),
    (re.compile(r"lighttpd|boa|goahead|mini_httpd|thttpd", re.I), "Embedded Web UI"),
]

_PORT_HINTS = {
    554: "IP Camera",
    8554: "IP Camera",
    1883: "MQTT Device",
    8883: "MQTT Device",
    5683: "CoAP Sensor",
    5684: "CoAP Sensor",
    9100: "Printer",
    515: "Printer",
    631: "Printer",
}


def infer_device_type(
    vendor: str, hostname: str, ports: List[int], banners: Dict[int, str], headers: Dict[str, str]
) -> str:
    haystack = " ".join([vendor, hostname] + list(banners.values()))
    for rx, label in _VENDOR_HINTS:
        if rx.search(vendor or "") or rx.search(hostname or ""):
            return label
    for rx, label in _BANNER_HINTS:
        if rx.search(haystack):
            return label
    for p in ports:
        if p in _PORT_HINTS:
            return _PORT_HINTS[p]
    if headers.get("server"):
        for rx, label in _BANNER_HINTS:
            if rx.search(headers["server"]):
                return label
    return "Unknown Device"


_OS_PATTERNS = [
    (re.compile(r"linux\s*([\d.]+)?", re.I), "Linux"),
    (re.compile(r"ubuntu", re.I), "Ubuntu Linux"),
    (re.compile(r"debian", re.I), "Debian Linux"),
    (re.compile(r"openwrt", re.I), "OpenWrt"),
    (re.compile(r"busybox", re.I), "BusyBox Linux"),
    (re.compile(r"windows", re.I), "Windows"),
    (re.compile(r"vxworks", re.I), "VxWorks"),
    (re.compile(r"freebsd", re.I), "FreeBSD"),
]

_FIRMWARE_PATTERNS = [
    re.compile(r"(?:firmware|fw|version)[\s:=/]*([\w.\-]{2,32})", re.I),
    re.compile(r"(?:v)(\d+\.\d+(?:\.\d+)*)", re.I),
]


def infer_os_and_firmware(banners: Dict[int, str], headers: Dict[str, str]) -> Dict[str, str]:
    blob = " ".join(list(banners.values()) + [headers.get("server", "")])
    os_guess = ""
    for rx, name in _OS_PATTERNS:
        if rx.search(blob):
            os_guess = name
            break
    fw = ""
    for rx in _FIRMWARE_PATTERNS:
        m = rx.search(blob)
        if m:
            fw = m.group(1)
            break
    return {"os": os_guess or "Unknown", "firmware": fw or "Unknown"}


# --------------------------------------------------------------------------- #
# Orchestrator
# --------------------------------------------------------------------------- #
class Fingerprinter:
    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("fingerprint", {}) or {}
        self.banner_timeout = float(cfg.get("banner_timeout", 3))
        self.http_timeout = float(cfg.get("http_timeout", 5))
        self.mqtt_timeout = float(cfg.get("mqtt_timeout", 4))
        self.coap_timeout = float(cfg.get("coap_timeout", 4))

    def run(self, devices: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []

        for dev in devices:
            ip = dev["ip"]
            ports = dev.get("ports", []) or []
            banners: Dict[int, str] = {}
            headers: Dict[str, str] = {}

            for p in ports:
                pnum = p["port"]
                banner = grab_banner(ip, pnum, self.banner_timeout)
                if banner:
                    banners[pnum] = banner[:512]
                    p["banner"] = banner[:512]

                if pnum in _HTTP_PORTS or pnum in _TLS_PORTS:
                    hdrs = http_headers(
                        ip, pnum, self.http_timeout, use_tls=(pnum in _TLS_PORTS)
                    )
                    if hdrs:
                        headers.update(hdrs)
                        p["http_headers"] = {k: v for k, v in hdrs.items() if not k.startswith("_")}

                if pnum in (1883, 8883):
                    res = mqtt_probe(ip, pnum, self.mqtt_timeout)
                    if res:
                        p["mqtt"] = res
                        if res.get("anonymous_allowed"):
                            findings.append(
                                Finding(
                                    id=f"mqtt-anon-{ip}-{pnum}",
                                    title="MQTT broker permits anonymous connections",
                                    severity="critical",
                                    category="insecure_protocol",
                                    description=(
                                        f"The MQTT broker on {ip}:{pnum} accepted a CONNECT "
                                        "without credentials (CONNACK rc=0). Anyone on the "
                                        "network can publish/subscribe."
                                    ),
                                    asset=ip,
                                    evidence={"port": pnum, "connack_rc": 0},
                                )
                            )

                if pnum == 5683:
                    payload = coap_probe(ip, pnum, self.coap_timeout)
                    if payload:
                        p["coap"] = payload[:512]

            dev["banners"] = banners
            dev["http_headers"] = headers
            dev["device_type"] = infer_device_type(
                dev.get("vendor", ""),
                dev.get("hostname", ""),
                [p["port"] for p in ports],
                banners,
                headers,
            )
            dev.update(infer_os_and_firmware(banners, headers))

            if headers.get("server") and not headers.get("x-content-type-options"):
                findings.append(
                    Finding(
                        id=f"http-headers-{ip}",
                        title="Web interface missing hardening headers",
                        severity="low",
                        category="web_hardening",
                        description=(
                            f"HTTP server on {ip} does not set X-Content-Type-Options "
                            "or related hardening headers."
                        ),
                        asset=ip,
                        evidence={"server": headers.get("server", "")},
                    )
                )

        return findings
