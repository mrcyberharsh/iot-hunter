"""Conservative service fingerprinting for authorized local device inventory."""
import copy
import logging
import re
import socket
import threading
import time
from collections import OrderedDict

import requests

logger = logging.getLogger("iothunter.fingerprint")
NVD_CACHE_TTL_SECONDS = 3600
NVD_CACHE_MAX_ENTRIES = 1024
NVD_REQUEST_TIMEOUT_SECONDS = 8
NVD_MAX_ATTEMPTS = 2
NVD_RETRY_DELAY_SECONDS = 0.25
_nvd_cache = OrderedDict()
_nvd_cache_lock = threading.Lock()
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
        ("apache", ["apache"]),
        ("nginx", ["nginx"]),
        ("ssh", ["ssh"]),
        ("telnet", ["telnet"]),
        ("mqtt", ["mqtt", "mosquitto"]),
        ("http", ["http"]),
        ("ftp", ["ftp"]),
        ("smtp", ["smtp"]),
        ("mysql", ["mysql"]),
        ("redis", ["redis"]),
        ("postgresql", ["postgresql", "postgres"]),
        ("mongodb", ["mongodb"]),
    ]

    for service, keywords in patterns:
        for keyword in keywords:
            if re.search(rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])", text, re.I):
                version_match = re.search(
                    r"(?:\b|[_/\s])v?([0-9]+(?:\.[0-9]+){0,3}(?:[-_][A-Za-z0-9]+)?)",
                    text,
                    re.I,
                )
                version = version_match.group(1) if version_match else None

                if service == "ssh":
                    # "SSH-2.0-OpenSSH_8.9p1" -> 2.0 is the protocol version; the
                    # software version (8.9p1) is what matters for CVE lookups.
                    ssh_match = re.search(r"(?:OpenSSH|dropbear|libssh)[_\s-]+v?([0-9]+(?:\.[0-9]+)*(?:p[0-9]+)?)", text, re.I)
                    if ssh_match:
                        version = ssh_match.group(1)
                    else:
                        proto = re.search(r"SSH-([0-9]+\.[0-9]+)", text, re.I)
                        version = proto.group(1) if proto else version

                return service, version
    return "unknown", None


def query_nvd_cves(service_name, version=None, results_per_page=5):
    """Look up public vulnerability references; results require manual validation."""
    if not service_name:
        return []
    service = str(service_name).strip()
    if not service or service.casefold() == "unknown":
        return []
    if isinstance(results_per_page, bool) or not isinstance(results_per_page, int):
        raise TypeError("results_per_page must be an integer.")
    limit = min(max(1, results_per_page), 10)
    query = service if version is None else f"{service} {str(version).strip()}"
    cache_key = (query.casefold(), limit)
    cached = _get_cached_nvd_result(cache_key)
    if cached is not None:
        return cached

    for attempt in range(NVD_MAX_ATTEMPTS):
        try:
            response = requests.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={
                    "keywordSearch": query,
                    "resultsPerPage": str(limit),
                },
                timeout=NVD_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            results = _parse_nvd_response(response.json(), limit)
        except requests.RequestException as exc:
            response = exc.response
            status_code = response.status_code if response is not None else None
            retryable = (
                status_code is None
                or status_code == 429
                or status_code >= 500
            )
            if retryable and attempt + 1 < NVD_MAX_ATTEMPTS:
                time.sleep(NVD_RETRY_DELAY_SECONDS * (2**attempt))
                continue
            logger.warning("NVD lookup failed for %s: %s", query, exc)
            return []
        except (ValueError, TypeError) as exc:
            logger.warning("NVD returned an invalid response for %s: %s", query, exc)
            return []

        _cache_nvd_result(cache_key, results)
        return copy.deepcopy(results)
    return []


def _parse_nvd_response(payload, limit):
    if not isinstance(payload, dict):
        raise TypeError("NVD response must be a JSON object.")
    if "vulnerabilities" not in payload:
        raise ValueError("NVD response is missing vulnerabilities.")
    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise TypeError("NVD vulnerabilities must be a JSON array.")

    results = []
    for item in vulnerabilities[:limit]:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve")
        if not isinstance(cve, dict) or not cve.get("id"):
            continue
        descriptions = cve.get("descriptions")
        first_description = (
            next((entry for entry in descriptions if isinstance(entry, dict)), {})
            if isinstance(descriptions, list)
            else {}
        )
        description = first_description.get("value", "No description available")
        results.append(
            {
                "id": cve["id"],
                "description": (
                    description
                    if isinstance(description, str)
                    else "No description available"
                ),
                "published": cve.get("published"),
            }
        )
    return results


def _get_cached_nvd_result(cache_key):
    now = time.monotonic()
    with _nvd_cache_lock:
        cached = _nvd_cache.get(cache_key)
        if cached is None:
            return None
        expires_at, results = cached
        if expires_at <= now:
            del _nvd_cache[cache_key]
            return None
        _nvd_cache.move_to_end(cache_key)
        return copy.deepcopy(results)


def _cache_nvd_result(cache_key, results):
    now = time.monotonic()
    with _nvd_cache_lock:
        expired = [
            key
            for key, (expires_at, _) in _nvd_cache.items()
            if expires_at <= now
        ]
        for key in expired:
            del _nvd_cache[key]
        _nvd_cache[cache_key] = (
            now + NVD_CACHE_TTL_SECONDS,
            copy.deepcopy(results),
        )
        _nvd_cache.move_to_end(cache_key)
        while len(_nvd_cache) > NVD_CACHE_MAX_ENTRIES:
            _nvd_cache.popitem(last=False)


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
