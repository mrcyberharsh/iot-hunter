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
import os
import queue
import re
import select
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import warnings
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

FIRMWARE_EXTENSIONS = {".bin", ".img", ".tar", ".squashfs"}
MAX_FIRMWARE_FILE_SIZE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_FILE_SIZE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_TOTAL_SIZE_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_STRINGS_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_STRING_LINE_BYTES = 256 * 1024
MAX_STRINGS_PER_FILE = 100_000
MAX_FIRMWARE_FINDINGS_PER_FILE = 1_000
MAX_FIRMWARE_FINDINGS = 10_000
MAX_FINDING_MATCH_CHARS = 1_024
EXTRACTION_TIMEOUT_SECONDS = 60
EXTRACTION_MONITOR_INTERVAL_SECONDS = 0.05
_STREAM_CHUNK_BYTES = 64 * 1024
_BWRAP_EXECUTABLE = shutil.which("bwrap")

_EXTRACTION_SANDBOX_HELPER = """
import os
import resource
import signal
import subprocess
import sys
import time

output_dir, max_file_size, *command = sys.argv[1:]
max_file_size = int(max_file_size)
os.makedirs(output_dir, mode=0o700, exist_ok=True)
resource.setrlimit(resource.RLIMIT_FSIZE, (max_file_size, max_file_size))
environment = {
    "HOME": output_dir,
    "LANG": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "TMPDIR": output_dir,
}

child = None

def terminate_child(signum, _frame):
    if child is not None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        time.sleep(0.05)
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    raise SystemExit(128 + signum)

signal.signal(signal.SIGTERM, terminate_child)
signal.signal(signal.SIGINT, terminate_child)
child = subprocess.Popen(
    command,
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    env=environment,
    start_new_session=True,
)
sys.stdout.write(f"STARTED {os.getpid()} {child.pid}\\n")
sys.stdout.flush()
return_code = child.wait()
try:
    os.killpg(child.pid, signal.SIGTERM)
except ProcessLookupError:
    pass
time.sleep(0.05)
try:
    os.killpg(child.pid, signal.SIGKILL)
except ProcessLookupError:
    pass
if return_code:
    raise SystemExit(return_code)
sys.stdout.write("READY\\n")
sys.stdout.flush()
sys.stdin.buffer.read(1)
"""

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
BEARER_TOKEN_PATTERN = re.compile(
    r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}"
)
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)
PRIVATE_KEY_BLOCK_PATTERN = re.compile(
    r"-----BEGIN ([A-Z0-9 ]*PRIVATE KEY)-----.*?-----END \1-----",
    re.IGNORECASE | re.DOTALL,
)


def redact_sensitive_text(value: str) -> str:
    """Redact recognizable secret material from text written to a report."""
    redacted = PRIVATE_KEY_BLOCK_PATTERN.sub("[REDACTED]", value)
    for pattern in (
        AWS_KEY_PATTERN,
        HARD_CODED_PASSWORD_PATTERN,
        API_TOKEN_PATTERN,
        BEARER_TOKEN_PATTERN,
        JWT_PATTERN,
        PRIVATE_KEY_PATTERN,
    ):
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _process_group_options() -> dict[str, Any]:
    if os.name == "nt":
        return {
            "creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        }
    return {"start_new_session": True}


def _signal_process_tree(process: subprocess.Popen, sig: int) -> None:
    if os.name == "posix":
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass
    elif sig == signal.SIGTERM:
        process.terminate()
    else:
        process.kill()


def _terminate_process_tree(
    process: subprocess.Popen, terminate_descendants: bool = False
) -> None:
    if process.poll() is None:
        _signal_process_tree(process, signal.SIGTERM)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    if os.name == "posix" and terminate_descendants:
        _signal_process_tree(process, signal.SIGKILL)
    elif process.poll() is None:
        process.kill()
    if process.poll() is None:
        process.wait()


def _parse_strings_line(line: bytes) -> tuple[int, str] | None:
    parts = line.decode("utf-8", errors="replace").strip().split(maxsplit=1)
    if len(parts) != 2:
        return None
    try:
        offset = int(parts[0])
    except ValueError:
        return None
    text = parts[1].strip()
    return (offset, text) if text else None


def _read_stream_in_chunks(stream, chunks: queue.Queue, stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            chunk = stream.read(_STREAM_CHUNK_BYTES)
            if not chunk:
                break
            while not stop.is_set():
                try:
                    chunks.put(chunk, timeout=0.05)
                    break
                except queue.Full:
                    continue
    except OSError as exc:
        while not stop.is_set():
            try:
                chunks.put(exc, timeout=0.05)
                break
            except queue.Full:
                continue
    finally:
        while not stop.is_set():
            try:
                chunks.put(None, timeout=0.05)
                break
            except queue.Full:
                continue


def _iter_strings_from_tool(
    executable: str, file_path: Path
) -> Iterator[tuple[int, str]]:
    process = subprocess.Popen(
        [executable, "-a", "-t", "d", str(file_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        **_process_group_options(),
    )
    if process.stdout is None:
        _terminate_process_tree(process)
        raise RuntimeError("Could not read strings command output.")

    chunks: queue.Queue = queue.Queue(maxsize=4)
    stop_reader = threading.Event()
    reader = threading.Thread(
        target=_read_stream_in_chunks,
        args=(process.stdout, chunks, stop_reader),
        daemon=True,
    )
    reader.start()
    deadline = time.monotonic() + EXTRACTION_TIMEOUT_SECONDS
    output_bytes = 0
    line_count = 0
    pending = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Firmware strings extraction timed out.")
            try:
                chunk = chunks.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                if process.poll() is not None and not reader.is_alive():
                    break
                continue
            if chunk is None:
                break
            if isinstance(chunk, BaseException):
                raise OSError("Could not read strings command output.") from chunk

            output_bytes += len(chunk)
            if output_bytes > MAX_STRINGS_OUTPUT_BYTES:
                raise ValueError("Firmware strings output exceeds the supported size.")

            pending.extend(chunk)
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    if len(pending) > MAX_STRING_LINE_BYTES:
                        raise ValueError("Firmware contains an oversized printable string.")
                    break
                if newline > MAX_STRING_LINE_BYTES:
                    raise ValueError("Firmware contains an oversized printable string.")
                line = bytes(pending[:newline])
                del pending[: newline + 1]
                line_count += 1
                if line_count > MAX_STRINGS_PER_FILE:
                    raise ValueError("Firmware contains too many printable strings.")
                parsed = _parse_strings_line(line)
                if parsed is not None:
                    yield parsed

        if pending:
            line_count += 1
            if line_count > MAX_STRINGS_PER_FILE:
                raise ValueError("Firmware contains too many printable strings.")
            parsed = _parse_strings_line(bytes(pending))
            if parsed is not None:
                yield parsed

        remaining = max(0, deadline - time.monotonic())
        try:
            return_code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError("Firmware strings extraction timed out.") from exc
        if return_code != 0:
            raise RuntimeError("Firmware strings command failed.")
    except BaseException:
        _terminate_process_tree(process)
        raise
    finally:
        stop_reader.set()
        process.stdout.close()
        reader.join(timeout=1)


def _iter_strings_fallback(file_path: Path) -> Iterator[tuple[int, str]]:
    """Scan bytes in bounded chunks when the system strings tool is unavailable."""
    try:
        source = file_path.open("rb")
    except OSError:
        return

    current = bytearray()
    offset = 0
    file_offset = 0
    output_bytes = 0
    string_count = 0
    with source:
        while chunk := source.read(_STREAM_CHUNK_BYTES):
            for index, byte in enumerate(chunk):
                position = file_offset + index
                if 32 <= byte < 127 or byte in (9, 10, 13):
                    output_bytes += 1
                    if output_bytes > MAX_STRINGS_OUTPUT_BYTES:
                        raise ValueError(
                            "Firmware strings output exceeds the supported size."
                        )
                    if not current:
                        offset = position
                    if len(current) >= MAX_STRING_LINE_BYTES:
                        raise ValueError(
                            "Firmware contains an oversized printable string."
                        )
                    current.append(byte)
                    continue

                if len(current) >= 8:
                    string_count += 1
                    if string_count > MAX_STRINGS_PER_FILE:
                        raise ValueError(
                            "Firmware contains too many printable strings."
                        )
                    yield offset, current.decode("utf-8", errors="ignore")
                current.clear()
                offset = position + 1
            file_offset += len(chunk)

    if len(current) >= 8:
        string_count += 1
        if string_count > MAX_STRINGS_PER_FILE:
            raise ValueError("Firmware contains too many printable strings.")
        yield offset, current.decode("utf-8", errors="ignore")


def _extract_strings(file_path: Path) -> Iterator[tuple[int, str]]:
    """Extract printable strings with offsets from a file.

    Uses the system `strings` tool when available, streaming its bounded output.
    Falls back to a chunked byte scan if the command is unavailable or fails.
    """
    strings_executable = shutil.which("strings")
    if strings_executable is not None:
        strings_output = _iter_strings_from_tool(strings_executable, file_path)
        try:
            first = next(strings_output)
        except (OSError, RuntimeError, TimeoutError):
            first = None
        if first is not None:
            try:
                yield first
                yield from strings_output
            except (OSError, RuntimeError, TimeoutError):
                yield from _iter_strings_fallback(file_path)
            else:
                return
    yield from _iter_strings_fallback(file_path)


def _iter_files(root: Path) -> Iterable[Path]:
    """Yield files recursively under a root directory."""
    if not root.exists():
        return []
    for path in root.rglob("*"):
        if not path.is_symlink() and path.is_file():
            yield path


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
    """Extract a bounded set of regular files to a directory."""
    if archive_path.stat().st_size > MAX_FIRMWARE_FILE_SIZE_BYTES:
        raise ValueError("Firmware archive exceeds the maximum supported size.")
    dest = destination.resolve()
    with tarfile.open(archive_path, "r:*") as archive:
        safe_members = []
        total_size = 0
        member_count = 0
        for member in archive:
            member_count += 1
            if member_count > MAX_ARCHIVE_MEMBERS:
                raise ValueError("Firmware archive contains too many entries.")
            # Skip links/devices and anything that would land outside destination
            # (path traversal such as "../../etc/cron.d/x" or absolute paths).
            if not (member.isfile() or member.isdir()):
                continue
            if member.size < 0 or member.size > MAX_EXTRACTED_FILE_SIZE_BYTES:
                raise ValueError("Firmware archive contains an oversized file.")
            total_size += member.size
            if total_size > MAX_EXTRACTED_TOTAL_SIZE_BYTES:
                raise ValueError("Firmware archive expands beyond the supported size.")
            target = (dest / member.name).resolve()
            if target != dest and dest not in target.parents:
                continue
            safe_members.append(member)
        kwargs = {"filter": "data"} if hasattr(tarfile, "data_filter") else {}
        archive.extractall(dest, members=safe_members, **kwargs)  # nosec B202 - members validated above


def _copy_extracted_tree(
    source: Path, destination: Path, deadline: float
) -> None:
    total_size = 0
    entry_count = 0
    for path in source.rglob("*"):
        if time.monotonic() >= deadline:
            raise RuntimeError("Firmware extraction timed out.")
        entry_count += 1
        if entry_count > MAX_ARCHIVE_MEMBERS:
            raise ValueError("Firmware extraction produced too many entries.")
        if path.is_symlink():
            continue
        try:
            if path.is_dir():
                target = destination / path.relative_to(source)
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            if not path.is_file():
                continue
            file_size = path.stat().st_size
        except FileNotFoundError:
            continue
        if file_size > MAX_EXTRACTED_FILE_SIZE_BYTES:
            raise ValueError("Firmware extraction produced an oversized file.")
        if total_size + file_size > MAX_EXTRACTED_TOTAL_SIZE_BYTES:
            raise ValueError("Firmware extraction exceeds the supported size.")

        target = destination / path.relative_to(source)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        copied_size = 0
        with path.open("rb") as source_file, target.open("xb") as target_file:
            while chunk := source_file.read(_STREAM_CHUNK_BYTES):
                copied_size += len(chunk)
                if copied_size > MAX_EXTRACTED_FILE_SIZE_BYTES:
                    raise ValueError("Firmware extraction produced an oversized file.")
                if total_size + copied_size > MAX_EXTRACTED_TOTAL_SIZE_BYTES:
                    raise ValueError("Firmware extraction exceeds the supported size.")
                target_file.write(chunk)
        total_size += copied_size


def _run_limited_extractor(command: list[str], destination: Path) -> None:
    """Run an extractor in a size-limited, read-only filesystem sandbox."""
    if _BWRAP_EXECUTABLE is None:
        warnings.warn(
            "bubblewrap is unavailable; external firmware extraction was skipped.",
            RuntimeWarning,
            stacklevel=2,
        )
        return

    input_path = Path(command[-1]).resolve()
    executable_path = Path(command[0]).resolve()
    with (
        tempfile.TemporaryDirectory(prefix="iothunter-firmware-sandbox-") as name,
        executable_path.open("rb") as executable_file,
        input_path.open("rb") as input_file,
    ):
        sandbox_tmp_root = Path(name).parent
        sandbox_destination = str(sandbox_tmp_root / Path(name).name)
        tool_directory = str(sandbox_tmp_root / "iothunter-tools")
        input_directory = str(sandbox_tmp_root / "iothunter-input")
        tool_destination = str(Path(tool_directory) / "extractor")
        input_destination = str(Path(input_directory) / "image")
        sandbox_command = [
            tool_destination if index == 0 else
            input_destination if argument == command[-1] else
            sandbox_destination if argument == str(destination) else argument
            for index, argument in enumerate(command)
        ]
        python_path = str(Path(sys.executable).resolve())
        bwrap_command = [
            _BWRAP_EXECUTABLE,
            "--die-with-parent",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
        ]
        for path in ("/home", "/root", "/var", "/run", "/proc"):
            if Path(path).is_dir() and not sandbox_tmp_root.is_relative_to(path):
                bwrap_command.extend(["--tmpfs", path])
        bwrap_command.extend(
            [
                "--size",
                str(MAX_EXTRACTED_TOTAL_SIZE_BYTES),
                "--tmpfs",
                str(sandbox_tmp_root),
                "--dev",
                "/dev",
                "--dir",
                sandbox_destination,
                "--dir",
                tool_directory,
                "--dir",
                input_directory,
                "--ro-bind-fd",
                str(executable_file.fileno()),
                tool_destination,
                "--ro-bind-fd",
                str(input_file.fileno()),
                input_destination,
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/local/bin:/usr/bin:/bin",
                "--setenv",
                "HOME",
                sandbox_destination,
                "--setenv",
                "TMPDIR",
                sandbox_destination,
                "--chdir",
                "/",
                "--",
                python_path,
                "-c",
                _EXTRACTION_SANDBOX_HELPER,
                sandbox_destination,
                str(MAX_EXTRACTED_FILE_SIZE_BYTES),
                *sandbox_command,
            ]
        )
        try:
            process = subprocess.Popen(
                bwrap_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                pass_fds=(executable_file.fileno(), input_file.fileno()),
                **_process_group_options(),
            )
        except OSError as exc:
            raise RuntimeError("Could not start the firmware extraction sandbox.") from exc

        deadline = time.monotonic() + EXTRACTION_TIMEOUT_SECONDS
        sandbox_tree = None
        extractor_process_group = None
        try:
            while True:
                if sandbox_tree is not None:
                    _validate_extracted_tree(sandbox_tree)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Firmware extraction timed out.")
                if process.poll() is not None:
                    raise RuntimeError(
                        f"{Path(command[0]).name} firmware extraction failed."
                    )
                readable, _, _ = select.select(
                    [process.stdout],
                    [],
                    [],
                    min(remaining, EXTRACTION_MONITOR_INTERVAL_SECONDS),
                )
                if not readable:
                    continue
                message = process.stdout.readline()
                if message.startswith(b"STARTED "):
                    try:
                        status, raw_sandbox_pid, raw_extractor_group = (
                            message.split()
                        )
                        if status != b"STARTED":
                            raise ValueError("Invalid process status.")
                        sandbox_pid = int(raw_sandbox_pid)
                        extractor_process_group = int(raw_extractor_group)
                    except (ValueError, TypeError) as exc:
                        raise RuntimeError(
                            "Firmware extraction sandbox returned an invalid status."
                        ) from exc
                    sandbox_tree = Path(
                        f"/proc/{sandbox_pid}/root{sandbox_destination}"
                    )
                    continue
                if message != b"READY\n" or sandbox_tree is None:
                    raise RuntimeError(
                        f"{Path(command[0]).name} firmware extraction failed."
                    )
                _validate_extracted_tree(sandbox_tree)
                _copy_extracted_tree(sandbox_tree, destination, deadline)
                process.stdin.write(b"x")
                process.stdin.flush()
                process.stdin.close()
                return_code = process.wait(
                    timeout=max(0, deadline - time.monotonic())
                )
                if return_code != 0:
                    raise RuntimeError(
                        f"{Path(command[0]).name} firmware extraction failed."
                    )
                _validate_extracted_tree(destination)
                return
        except BaseException:
            if extractor_process_group is not None:
                try:
                    os.killpg(extractor_process_group, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                time.sleep(0.05)
                try:
                    os.killpg(extractor_process_group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            _terminate_process_tree(process, terminate_descendants=True)
            raise
        finally:
            if process.stdout is not None:
                process.stdout.close()
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()


def _extract_squashfs_archive(archive_path: Path, destination: Path) -> None:
    """Attempt extraction of a squashfs image when unsquashfs is installed."""
    executable = shutil.which("unsquashfs")
    if executable is None:
        return
    _run_limited_extractor(
        [executable, "-d", str(destination), str(archive_path)],
        destination,
    )


def _extract_binwalk_image(file_path: Path, destination: Path) -> None:
    """Extract a firmware image using binwalk when it is available."""
    executable = shutil.which("binwalk")
    if executable is None:
        return
    _run_limited_extractor(
        [executable, "-e", "-M", "-C", str(destination), str(file_path)],
        destination,
    )


def _validate_extracted_tree(root: Path) -> None:
    total_size = 0
    entry_count = 0
    for path in root.rglob("*"):
        entry_count += 1
        if entry_count > MAX_ARCHIVE_MEMBERS:
            raise ValueError("Firmware extraction produced too many entries.")
        try:
            if path.is_symlink() or not path.is_file():
                continue
            file_size = path.stat().st_size
        except FileNotFoundError:
            continue
        if file_size > MAX_EXTRACTED_FILE_SIZE_BYTES:
            raise ValueError("Firmware extraction produced an oversized file.")
        total_size += file_size
        if total_size > MAX_EXTRACTED_TOTAL_SIZE_BYTES:
            raise ValueError("Firmware extraction exceeds the supported size.")


@contextmanager
def _candidate_paths_for_firmware(file_path: Path) -> Iterator[list[Path]]:
    """Keep extracted candidates alive for the duration of their scan."""
    candidates: list[Path] = [file_path]

    with tempfile.TemporaryDirectory(prefix="iothunter-firmware-") as temp_dir:
        temp_root = Path(temp_dir)
        suffix = file_path.suffix.lower()

        if shutil.which("binwalk") is not None and suffix in {".bin", ".img"}:
            _extract_binwalk_image(file_path, temp_root)

        if suffix == ".tar":
            try:
                _extract_tar_archive(file_path, temp_root)
            except tarfile.TarError as exc:
                raise ValueError("Firmware tar archive is invalid.") from exc

        if suffix == ".squashfs":
            _extract_squashfs_archive(file_path, temp_root)

        _validate_extracted_tree(temp_root)
        for item in _iter_files(temp_root):
            candidates.append(item)

        yield candidates


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

    if not file_path.is_file():
        raise ValueError("Firmware path must reference a regular file.")
    if file_path.stat().st_size > MAX_FIRMWARE_FILE_SIZE_BYTES:
        raise ValueError("Firmware file exceeds the maximum supported size.")

    if file_path.suffix.lower() not in FIRMWARE_EXTENSIONS and not file_path.name.lower().endswith(tuple(FIRMWARE_EXTENSIONS)):
        raise ValueError(f"Unsupported firmware extension for {path}")

    findings: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int, str]] = set()

    with _candidate_paths_for_firmware(file_path) as candidates:
        for candidate in candidates:
            if not candidate.exists() or not candidate.is_file():
                continue

            file_findings = 0
            for offset, text in _extract_strings(candidate):
                for finding in _scan_line_for_patterns(text, offset):
                    match = finding["match"][:MAX_FINDING_MATCH_CHARS]
                    key = (finding["type"], finding["offset"], match)
                    if key in seen_keys:
                        continue
                    file_findings += 1
                    if file_findings > MAX_FIRMWARE_FINDINGS_PER_FILE:
                        raise ValueError(
                            "Firmware file contains too many security findings."
                        )
                    if len(findings) >= MAX_FIRMWARE_FINDINGS:
                        raise ValueError(
                            "Firmware scan produced too many security findings."
                        )
                    seen_keys.add(key)
                    findings.append(
                        {
                            "file": str(candidate),
                            "type": finding["type"],
                            "pattern": finding["pattern"],
                            "offset": finding["offset"],
                            "match": match,
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
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
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
