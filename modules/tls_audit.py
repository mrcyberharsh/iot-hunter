"""
TLS / Certificate Hygiene Audit Module.

Checks TLS configuration on detected devices and reports weak
or misconfigured certificates. Non-destructive, read-only.
"""
import socket
import ssl
from datetime import datetime, timezone


WEAK_CIPHER_MARKERS = {"DES", "3DES", "RC4", "MD5", "NULL", "EXPORT", "ANON"}
WEAK_KEY_BITS = 2048
HTTP_ADMIN_PORTS = {80, 8080, 8888, 8888}


class TLSAuditResult:
    """Result of a TLS audit against a single (ip, port)."""

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.reachable = False
        self.certificate = None
        self.findings = []
        self.error = None

    def to_dict(self):
        return {
            "ip": self.ip,
            "port": self.port,
            "reachable": self.reachable,
            "certificate": self.certificate,
            "findings": self.findings,
            "error": self.error,
        }


def _finding(severity, code, message, remediation):
    return {
        "severity": severity,
        "code": code,
        "message": message,
        "remediation": remediation,
    }


def _fetch_certificate(ip, port, timeout=5):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as tls_sock:
            cert_dict = tls_sock.getpeercert()
            cipher = tls_sock.cipher()
            version = tls_sock.version()
    return cert_dict, cipher, version


def _parse_name_field(field_list):
    return {k: v for entry in field_list for k, v in entry}


def audit_tls(ip, port, timeout=5):
    """Audit TLS on a single port. Returns TLSAuditResult."""
    result = TLSAuditResult(ip, port)
    try:
        cert_dict, cipher, version = _fetch_certificate(ip, port, timeout)
        result.reachable = True
    except (socket.timeout, ConnectionRefusedError, OSError, ssl.SSLError) as e:
        result.error = f"{type(e).__name__}: {e}"
        return result
    except Exception as e:  # noqa: BLE001 — defensive, network is untrusted
        result.error = f"Unexpected: {e}"
        return result

    now = datetime.now(timezone.utc)

    subject = _parse_name_field(cert_dict.get("subject", []))
    issuer = _parse_name_field(cert_dict.get("issuer", []))
    expiry = None
    if cert_dict.get("notAfter"):
        try:
            expiry = datetime.strptime(
                cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    sans = [val for typ, val in cert_dict.get("subjectAltName", []) if typ == "DNS"]

    result.certificate = {
        "subject_cn": subject.get("commonName", ""),
        "issuer_org": issuer.get("organizationName", issuer.get("commonName", "")),
        "subject_alt_names": sans,
        "expiry": expiry.isoformat() if expiry else None,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
    }

    if expiry:
        days_left = (expiry - now).days
        if days_left < 0:
            result.findings.append(_finding(
                "high", "TLS_EXPIRED",
                f"Certificate expired {-days_left} days ago",
                "Renew the TLS certificate with a valid CA-signed one.",
            ))
        elif days_left < 30:
            result.findings.append(_finding(
                "medium", "TLS_EXPIRING_SOON",
                f"Certificate expires in {days_left} days",
                "Schedule certificate renewal before expiry.",
            ))

    if (subject.get("commonName")
            and issuer.get("commonName") == subject.get("commonName")):
        result.findings.append(_finding(
            "medium", "TLS_SELF_SIGNED",
            f"Self-signed certificate: {subject.get('commonName')}",
            "Replace with a trusted CA certificate for production devices.",
        ))

    if cipher:
        cipher_name = cipher[0].upper()
        for marker in WEAK_CIPHER_MARKERS:
            if marker in cipher_name:
                result.findings.append(_finding(
                    "high", "TLS_WEAK_CIPHER",
                    f"Weak cipher negotiated: {cipher[0]}",
                    f"Disable {marker}-based ciphers; require TLS 1.2+ with AEAD.",
                ))
                break

    if cipher and len(cipher) > 2 and isinstance(cipher[2], int) and 0 < cipher[2] < WEAK_KEY_BITS:
        result.findings.append(_finding(
            "medium", "TLS_WEAK_KEY",
            f"Key size {cipher[2]} bits is below recommended {WEAK_KEY_BITS}",
            "Use RSA 2048+ or ECDSA P-256+.",
        ))

    if version in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
        result.findings.append(_finding(
            "high", "TLS_OLD_VERSION",
            f"Obsolete TLS version: {version}",
            "Disable TLS 1.0/1.1 and require TLS 1.2+.",
        ))

    return result


def audit_ports(ip, ports, timeout=5):
    """Audit TLS on multiple ports. Returns list of TLSAuditResult."""
    return [audit_tls(ip, port, timeout) for port in ports]


def check_missing_tls(open_ports):
    """Flag HTTP admin ports without an HTTPS alternative."""
    findings = []
    has_https = bool({443, 8443} & set(open_ports))
    for port in open_ports:
        if port in HTTP_ADMIN_PORTS and not has_https:
            findings.append(_finding(
                "medium", "TLS_MISSING",
                f"HTTP admin port {port} open, no HTTPS alternative detected",
                "Enable HTTPS on the admin interface and disable plain HTTP.",
            ))
    return findings
