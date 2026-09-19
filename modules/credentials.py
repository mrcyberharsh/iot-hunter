"""
credentials.py - Local wordlist default-credential testing
Built by MR CYBER (Harsh Saini)
Rate-limited, only local wordlists, no external APIs.
"""
import socket
import time
import logging
import requests
from requests.auth import HTTPBasicAuth

logger = logging.getLogger("iothunter.credentials")


def load_wordlist(path):
    creds = []
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                user, pwd = line.split(":", 1)
                creds.append((user, pwd))
    except FileNotFoundError:
        logger.error("Wordlist not found at %s", path)
    return creds


def try_http_basic(ip, port, user, pwd, timeout=3):
    try:
        url = f"http://{ip}:{port}/"
        r = requests.get(url, auth=HTTPBasicAuth(user, pwd), timeout=timeout)
        return r.status_code == 200
    except requests.RequestException:
        return False


def try_telnet(ip, port, user, pwd, timeout=3):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            time.sleep(0.5)
            s.recv(1024)
            s.sendall((user + "\n").encode())
            time.sleep(0.5)
            s.recv(1024)
            s.sendall((pwd + "\n").encode())
            time.sleep(0.5)
            resp = s.recv(1024).decode(errors="ignore").lower()
            return "incorrect" not in resp and "denied" not in resp and "fail" not in resp
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def test_device_credentials(device, wordlist, max_attempts=3, delay=1.0):
    """Test only services that allow login (HTTP, Telnet). Rate-limited."""
    findings = []
    ports = device.get("open_ports", [])
    attempts_used = 0

    for user, pwd in wordlist:
        if attempts_used >= max_attempts:
            break

        hit = False
        if 80 in ports or 8080 in ports:
            port = 80 if 80 in ports else 8080
            if try_http_basic(device["ip"], port, user, pwd):
                hit = True
                findings.append({"ip": device["ip"], "service": "http", "port": port,
                                  "user": user, "password": pwd})

        if 23 in ports:
            if try_telnet(device["ip"], 23, user, pwd):
                hit = True
                findings.append({"ip": device["ip"], "service": "telnet", "port": 23,
                                  "user": user, "password": pwd})

        attempts_used += 1
        time.sleep(delay)  # rate limiting between attempts

        if hit:
            logger.warning("Default credentials found on %s", device["ip"])
            break  # stop after first confirmed hit for this device

    return findings


def run_credential_tests(devices, wordlist_path, max_attempts=3):
    wordlist = load_wordlist(wordlist_path)
    if not wordlist:
        print("[!] No wordlist loaded, skipping credential testing.")
        return []

    all_findings = []
    for device in devices:
        if not any(p in device.get("open_ports", []) for p in (23, 80, 8080)):
            continue
        findings = test_device_credentials(device, wordlist, max_attempts=max_attempts)
        all_findings.extend(findings)

    return all_findings
