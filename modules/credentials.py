"""Default-credential testing against HTTP, SSH, Telnet and MQTT.

Strictly rate-limited. Only reads a LOCAL wordlist. Never phones home.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

from .models import Finding

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Wordlist
# --------------------------------------------------------------------------- #
def load_wordlist(path: str) -> List[Tuple[str, str, str]]:
    """
    Parse the local wordlist. Supported line formats:
        username:password
        service:username:password
    Comments (#) and blank lines are ignored.
    """
    entries: List[Tuple[str, str, str]] = []
    if not path or not os.path.isfile(path):
        log.warning("Credential wordlist not found: %s", path)
        return entries

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) == 2:
                entries.append(("any", parts[0], parts[1]))
            elif len(parts) >= 3:
                entries.append((parts[0].lower(), parts[1], ":".join(parts[2:])))
    log.info("Loaded %d credential pairs from %s", len(entries), path)
    return entries


# --------------------------------------------------------------------------- #
# MQTT raw CONNECT (no external dependency)
# --------------------------------------------------------------------------- #
def _mqtt_str(s: str) -> bytes:
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


def _mqtt_remaining_length(n: int) -> bytes:
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


def mqtt_connect(
    ip: str, port: int, username: str, password: str, timeout: float
) -> bool:
    """Return True if the broker accepts these credentials."""
    client_id = "iot-hunter"
    flags = 0x02  # clean session
    payload = _mqtt_str(client_id)
    if username:
        flags |= 0x80
        payload += _mqtt_str(username)
    if password:
        flags |= 0x40
        payload += _mqtt_str(password)

    variable = _mqtt_str("MQTT") + bytes([4, flags]) + (30).to_bytes(2, "big")
    body = variable + payload
    packet = b"\x10" + _mqtt_remaining_length(len(body)) + body

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(packet)
            resp = sock.recv(8)
    except OSError:
        return False
    return len(resp) >= 4 and resp[0] == 0x20 and resp[3] == 0x00


# --------------------------------------------------------------------------- #
# Telnet login (raw socket, no deprecated telnetlib)
# --------------------------------------------------------------------------- #
class TelnetTester:
    def __init__(self, timeout: float):
        self.timeout = timeout

    def _recv_until(self, sock: socket.socket, tokens: List[bytes]) -> bytes:
        buf = b""
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                chunk = sock.recv(512)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            if any(t in buf.lower() for t in tokens):
                break
        return buf

    def _recv_all(self, sock: socket.socket) -> bytes:
        buf = b""
        sock.settimeout(1.0)
        while True:
            try:
                chunk = sock.recv(1024)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        return buf

    def try_login(self, ip: str, port: int, user: str, password: str) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                banner = self._recv_until(
                    sock, [b"login:", b"username:", b"user:", b"#", b"$"]
                )
                if not banner:
                    return False
                sock.sendall(user.encode() + b"\r\n")
                prompt = self._recv_until(sock, [b"password:", b"passcode:"])
                if not prompt:
                    return False
                sock.sendall(password.encode() + b"\r\n")
                time.sleep(0.6)
                resp = self._recv_all(sock).decode("utf-8", "replace").lower()
                if any(
                    bad in resp
                    for bad in ("incorrect", "invalid", "failed", "denied", "try again")
                ):
                    return False
                return bool(resp.strip())
        except OSError:
            return False


# --------------------------------------------------------------------------- #
# Credential tester
# --------------------------------------------------------------------------- #
_SUCCESS_MARKERS = (
    "logout",
    "log out",
    "sign out",
    "dashboard",
    "configuration",
    "settings",
    "welcome",
    "status",
    "system",
)
_FAILURE_MARKERS = (
    "invalid",
    "incorrect",
    "failed",
    "denied",
    "try again",
    "unauthorized",
)


class CredentialTester:
    def __init__(self, config: Dict[str, Any]):
        cfg = config.get("credentials", {}) or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.max_attempts = int(cfg.get("max_attempts_per_service", 3))
        self.delay = float(cfg.get("delay_between_attempts", 2.0))
        self.timeout = float(cfg.get("connect_timeout", 4.0))
        self.services = set(cfg.get("services", ["http", "ssh", "telnet", "mqtt"]))
        self.login_paths = cfg.get("http_login_paths", ["/", "/login"])
        self.wordlist = load_wordlist(cfg.get("wordlist_path", ""))
        self.telnet = TelnetTester(self.timeout)

    # ---- HTTP ---------------------------------------------------------- #
    def _http_baseline(self, ip: str, port: int, use_tls: bool) -> Optional[Any]:
        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{ip}:{port}/"
        try:
            return requests.get(
                url, timeout=self.timeout, verify=False, allow_redirects=False
            )
        except requests.RequestException:
            return None

    def _http_basic(
        self, ip: str, port: int, user: str, password: str, use_tls: bool
    ) -> bool:
        scheme = "https" if use_tls else "http"
        url = f"{scheme}://{ip}:{port}/"
        baseline = self._http_baseline(ip, port, use_tls)
        try:
            resp = requests.get(
                url,
                auth=(user, password),
                timeout=self.timeout,
                verify=False,
                allow_redirects=False,
            )
        except requests.RequestException:
            return False

        if baseline is not None:
            if baseline.status_code in (401, 403) and resp.status_code == 200:
                return True
            if baseline.status_code == 200 and resp.status_code == 200:
                # Look for a meaningful change in body length + success markers
                text = resp.text.lower()
                if any(m in text for m in _SUCCESS_MARKERS) and not any(
                    m in text for m in _FAILURE_MARKERS
                ):
                    if abs(len(resp.text) - len(baseline.text)) > 50:
                        return True
        return False

    def _http_form(
        self, ip: str, port: int, user: str, password: str, use_tls: bool
    ) -> bool:
        scheme = "https" if use_tls else "http"
        base = f"{scheme}://{ip}:{port}"
        user_fields = ["username", "user", "login", "usr", "email", "name"]
        pass_fields = ["password", "pass", "pwd", "passwd", "passw"]

        for path in self.login_paths:
            url = base + path
            for uf in user_fields:
                for pf in pass_fields:
                    try:
                        resp = requests.post(
                            url,
                            data={uf: user, pf: password, "submit": "Login"},
                            timeout=self.timeout,
                            verify=False,
                            allow_redirects=True,
                        )
                    except requests.RequestException:
                        continue
                    if resp.status_code not in (200, 302):
                        continue
                    text = resp.text.lower()
                    if any(m in text for m in _FAILURE_MARKERS):
                        continue
                    if any(m in text for m in _SUCCESS_MARKERS) or resp.history:
                        return True
                    if resp.cookies and resp.cookies.get_dict():
                        return True
        return False

    def _test_http(
        self, ip: str, port: int, user: str, password: str
    ) -> bool:
        use_tls = port in (443, 8443, 9443)
        return self._http_basic(ip, port, user, password, use_tls) or self._http_form(
            ip, port, user, password, use_tls
        )

    # ---- SSH ----------------------------------------------------------- #
    def _test_ssh(self, ip: str, port: int, user: str, password: str) -> bool:
        try:
            import paramiko  # local import keeps startup fast
        except ImportError:
            log.warning("paramiko not installed — SSH credential testing disabled")
            return False

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=ip,
                port=port,
                username=user,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception:
            return False
        finally:
            try:
                client.close()
            except Exception:
                pass

    # ---- Dispatcher ---------------------------------------------------- #
    def _test_service(
        self, service: str, ip: str, port: int, user: str, password: str
    ) -> bool:
        if service == "http":
            return self._test_http(ip, port, user, password)
        if service == "ssh":
            return self._test_ssh(ip, port, user, password)
        if service == "telnet":
            return self.telnet.try_login(ip, port, user, password)
        if service == "mqtt":
            return mqtt_connect(ip, port, user, password, self.timeout)
        return False

    # ---- Orchestrator -------------------------------------------------- #
    def run(self, devices: List[Dict[str, Any]]) -> List[Finding]:
        findings: List[Finding] = []
        if not self.enabled:
            log.info("Credential testing disabled in config")
            return findings
        if not self.wordlist:
            log.warning("Empty wordlist — skipping credential testing")
            return findings

        service_ports = {
            "http": lambda p: p in (80, 81, 88, 443, 8000, 8080, 8081, 8443, 8888, 9443),
            "ssh": lambda p: p == 22,
            "telnet": lambda p: p in (23, 2323),
            "mqtt": lambda p: p in (1883, 8883),
        }

        for dev in devices:
            ip = dev["ip"]
            for p in dev.get("ports", []):
                pnum = p["port"]
                for service, matcher in service_ports.items():
                    if service not in self.services or not matcher(pnum):
                        continue

                    # Only attempt services that actually look login-capable
                    if service == "mqtt" and "mqtt" not in p and pnum not in (1883, 8883):
                        continue

                    attempts = 0
                    for entry_service, user, password in self.wordlist:
                        if attempts >= self.max_attempts:
                            break
                        if entry_service not in ("any", service):
                            continue
                        attempts += 1
                        log.info(
                            "Testing %s://%s:%s as %s (attempt %d/%d)",
                            service, ip, pnum, user, attempts, self.max_attempts,
                        )
                        try:
                            ok = self._test_service(service, ip, pnum, user, password)
                        except Exception as exc:
                            log.debug("Credential test error %s:%s — %s", ip, pnum, exc)
                            ok = False

                        if ok:
                            findings.append(
                                Finding(
                                    id=f"weak-cred-{ip}-{pnum}-{user}",
                                    title=f"Default credentials accepted on {service.upper()}",
                                    severity="critical",
                                    category="default_credentials",
                                    description=(
                                        f"The {service.upper()} service on {ip}:{pnum} accepted "
                                        f"username '{user}' with a well-known default password."
                                    ),
                                    asset=ip,
                                    evidence={
                                        "service": service,
                                        "port": pnum,
                                        "username": user,
                                        "mac": dev.get("mac", ""),
                                        "vendor": dev.get("vendor", ""),
                                    },
                                )
                            )
                            break
                        time.sleep(self.delay)

        return findings
