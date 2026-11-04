#!/usr/bin/env python3
"""Lightweight firmware secret scanning for IoT Hunter.

This module accepts common firmware images and archives (.bin, .img, .tar,
.squashfs) and scans extracted strings for common secret types, including:
- AWS access keys
- RSA/EC private keys
- hardcoded passwords
- API tokens
- JWT material
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Iterable

FIRMWARE_EXTENSIONS = {".bin", ".img", ".tar", ".squashfs"}

AWS_KEY_PATTERN = re.compile(
    r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])",
    re.IGNORECASE,
)
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN (?:RSA|EC|DSA|OPENSSH|PRIVATE) KEY-----",
    re.IGNORECASE,
)
HARD_CODED_PASSWORD_PATTERN = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|pass)\s*[:=]\s*[\"']?([A-Za-z0-9!@#$%^&*._-]{8,})"
)
API_TOKEN_PATTERN = re.compile(
    r"(?i)(?:api[_-]?key|token|auth[_-]?token|bearer)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})"
)
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)


def _run_command(command: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return the exit code, stdout, and stderr."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return result.returncode, result.stdout, result.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 1, "", "Command failed"


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield files recursively under a root directory."""
    if not root.exists():
        return []
    for path in root.rglob("*"):
        if path.is_file():
            yield path


def _extract_strings(file_path: Path) -> list[tuple[int, str]]:
    """Extract printable strings with offsets from a file.

    Uses the system `strings` tool when available, with a best-effort fallback
    to a manual byte scan when it is not installed.
    """
    if shutil.which("strings") is not None:
        code, stdout, _ = _run_command(["strings", "-a", "-t", "d", str(file_path)])
        if code == 0 and stdout.strip():
            entries: list[tuple[int, str]] = []
            for line in stdout.splitlines():
                parts = line.strip().split(maxsplit=1)
                if len(parts) < 2:
                    continue
                try:
                    offset = int(parts[0])
                except ValueError:
                    continue
                text = parts[1].strip()
                if text:
                    entries.append((offset, text))
            return entries

    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    ascii_chunks: list[tuple[int, str]] = []
    current = bytearray()
    offset = 0
    for index, byte in enumerate(data):
        if 32 <= byte < 127 or byte in (9, 10, 13):
            current.append(byte)
        else:
            if len(current) >= 8:
                ascii_chunks.append((offset, current.decode("utf-8", errors="ignore")))
            current.clear()
            offset = index + 1
    if len(current) >= 8:
        ascii_chunks.append((offset, current.decode("utf-8", errors="ignore")))
    return ascii_chunks


def _scan_line_for_patterns(line: str, offset: int) -> list[dict[str, Any]]:
    """Scan a string line for known secret patterns and return findings."""
    findings: list[dict[str, Any]] = []

    aws_match = AWS_KEY_PATTERN.search(line)
    if aws_match:
        findings.append(
            {
                "type": "aws_key",
                "pattern": "AWS key",
                "offset": offset,
                "match": aws_match.group(0),
                "severity": "CRITICAL",
            }
        )

    private_match = PRIVATE_KEY_PATTERN.search(line)
    if private_match:
        findings.append(
            {
                "type": "private_key",
                "pattern": "Private key header",
                "offset": offset,
                "match": private_match.group(0),
                "severity": "CRITICAL",
            }
        )

    password_match = HARD_CODED_PASSWORD_PATTERN.search(line)
    if password_match:
        findings.append(
            {
                "type": "hardcoded_password",
                "pattern": "Password assignment",
                "offset": offset,
                "match": password_match.group(0),
                "severity": "HIGH",
            }
        )

    token_match = API_TOKEN_PATTERN.search(line)
    if token_match:
        findings.append(
            {
                "type": "api_token",
                "pattern": "API token assignment",
                "offset": offset,
                "match": token_match.group(0),
                "severity": "HIGH",
            }
        )

    jwt_match = JWT_PATTERN.search(line)
    if jwt_match:
        findings.append(
            {
                "type": "jwt",
                "pattern": "JWT token",
                "offset": offset,
                "match": jwt_match.group(0),
                "severity": "HIGH",
            }
        )

    return findings


def _extract_tar_archive(archive_path: Path, destination: Path) -> None:
    """Extract a tar archive to a directory."""
    with tarfile.open(archive_path, "r:*") as archive:
        archive.extractall(destination)


def _extract_squashfs_archive(archive_path: Path, destination: Path) -> None:
    """Attempt extraction of a squashfs image when unsquashfs is installed."""
    if shutil.which("unsquashfs") is None:
        return
    _run_command(["unsquashfs", "-d", str(destination), str(archive_path)])


def _extract_binwalk_image(file_path: Path, destination: Path) -> None:
    """Extract a firmware image using binwalk when it is available."""
    if shutil.which("binwalk") is None:
        return
    _run_command(["binwalk", "-e", "-M", str(file_path)])
    extracted_root = file_path.parent / f"{file_path.name}_extracted"
    if extracted_root.exists():
        for item in _iter_files(extracted_root):
            if item.is_file():
                target = destination / item.relative_to(extracted_root)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(item.read_bytes())


def _candidate_paths_for_firmware(file_path: Path) -> list[Path]:
    """Return candidate files to scan, including extracted contents."""
    candidates: list[Path] = [file_path]

    with tempfile.TemporaryDirectory(prefix="iothunter-firmware-") as temp_dir:
        temp_root = Path(temp_dir)
        suffix = file_path.suffix.lower()

        if shutil.which("binwalk") is not None and suffix in {".bin", ".img"}:
            _extract_binwalk_image(file_path, temp_root)

        if suffix == ".tar":
            try:
                _extract_tar_archive(file_path, temp_root)
            except tarfile.TarError:
                pass

        if suffix == ".squashfs":
            _extract_squashfs_archive(file_path, temp_root)

        for item in _iter_files(temp_root):
            if item.is_file():
                candidates.append(item)

    return candidates


def scan_firmware_file(path: str) -> list[dict[str, Any]]:
    """Scan a firmware file or archive for secrets.

    Args:
        path: File path to the firmware image.

    Returns:
        A list of finding dictionaries with type, file offset, match excerpt,
        and severity.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Firmware file does not exist: {path}")

    if file_path.suffix.lower() not in FIRMWARE_EXTENSIONS and not file_path.name.lower().endswith(tuple(FIRMWARE_EXTENSIONS)):
        raise ValueError(f"Unsupported firmware extension for {path}")

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int, str]] = set()

    for candidate in _candidate_paths_for_firmware(file_path):
        if not candidate.exists() or not candidate.is_file():
            continue

        for offset, text in _extract_strings(candidate):
            for finding in _scan_line_for_patterns(text, offset):
                key = (finding["type"], finding["offset"], finding["match"])
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                findings.append(
                    {
                        "file": str(candidate),
                        "type": finding["type"],
                        "pattern": finding["pattern"],
                        "offset": finding["offset"],
                        "match": finding["match"],
                        "severity": finding["severity"],
                    }
                )

    return sorted(findings, key=lambda item: (item["offset"], item["type"]))


def main() -> int:
    """Scan a firmware image from the command line."""
    parser = argparse.ArgumentParser(description="Firmware secret scanner for IoT images.")
    parser.add_argument("firmware", help="Path to a .bin, .img, .tar, or .squashfs file.")
    args = parser.parse_args()

    try:
        findings = scan_firmware_file(args.firmware)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[!] {exc}")
        return 1

    if not findings:
        print(f"[+] No secret patterns found in {args.firmware}")
        return 0

    for finding in findings:
        print(
            f"[!] {finding['type']} | file={finding['file']} | "
            f"offset={finding['offset']} | match={finding['match'][:80]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
