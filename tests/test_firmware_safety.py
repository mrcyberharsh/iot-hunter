import io
import os
import tarfile
import time
from pathlib import Path

import pytest
from modules.firmware import _extract_tar_archive, scan_firmware_file

from modules import firmware

pytestmark = pytest.mark.unit


def _make_tar(path, entries):
    with tarfile.open(path, "w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def _write_executable(path, source):
    path.write_text(f"#!/usr/bin/env python3\n{source}", encoding="utf-8")
    path.chmod(0o700)
    return path


def _track_extractor_process(monkeypatch, pid_file):
    original_popen = firmware.subprocess.Popen

    def tracked_popen(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        pid_file.write_text(str(process.pid), encoding="utf-8")
        return process

    monkeypatch.setattr(firmware.subprocess, "Popen", tracked_popen)


def _track_temporary_directories(monkeypatch, parent):
    original_temporary_directory = firmware.tempfile.TemporaryDirectory
    created = []

    def tracked_temporary_directory(*args, **kwargs):
        kwargs["dir"] = parent
        directory = original_temporary_directory(*args, **kwargs)
        created.append(Path(directory.name))
        return directory

    monkeypatch.setattr(
        firmware.tempfile, "TemporaryDirectory", tracked_temporary_directory
    )
    return created


def _assert_temporary_directories_removed(directories):
    assert directories
    assert all(not directory.exists() for directory in directories)


def _assert_process_stopped(pid):
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_tar_path_traversal_is_blocked(tmp_path):
    archive = tmp_path / "fw.tar"
    _make_tar(archive, {"ok/file.txt": b"hello", "../escaped.txt": b"bad", "/abs.txt": b"bad"})
    dest = tmp_path / "out"
    dest.mkdir()
    _extract_tar_archive(archive, dest)
    assert (dest / "ok" / "file.txt").read_text() == "hello"
    assert not (tmp_path / "escaped.txt").exists()
    assert not Path("/abs.txt").exists()


def test_firmware_tar_scans_extracted_members_before_cleanup(tmp_path):
    archive = tmp_path / "firmware.tar"
    _make_tar(
        archive,
        {"etc/device.conf": b"password=supersecret-device-password"},
    )

    findings = scan_firmware_file(str(archive))

    assert any(
        Path(finding["file"]).name == "device.conf"
        and finding["type"] == "hardcoded_password"
        for finding in findings
    )


def test_tar_archive_rejects_oversized_member_before_extraction(tmp_path, monkeypatch):
    archive = tmp_path / "large.tar"
    _make_tar(archive, {"large.bin": b"12345"})
    destination = tmp_path / "out"
    destination.mkdir()
    monkeypatch.setattr(firmware, "MAX_EXTRACTED_FILE_SIZE_BYTES", 4)

    with pytest.raises(ValueError, match="oversized file"):
        _extract_tar_archive(archive, destination)

    assert list(destination.iterdir()) == []


def test_tar_archive_enforces_total_expansion_and_member_limits(tmp_path, monkeypatch):
    archive = tmp_path / "many.tar"
    _make_tar(archive, {"one": b"123", "two": b"456"})
    destination = tmp_path / "out"
    destination.mkdir()
    monkeypatch.setattr(firmware, "MAX_EXTRACTED_TOTAL_SIZE_BYTES", 5)

    with pytest.raises(ValueError, match="expands beyond"):
        _extract_tar_archive(archive, destination)

    monkeypatch.setattr(firmware, "MAX_EXTRACTED_TOTAL_SIZE_BYTES", 10)
    monkeypatch.setattr(firmware, "MAX_ARCHIVE_MEMBERS", 1)
    with pytest.raises(ValueError, match="too many entries"):
        _extract_tar_archive(archive, destination)

    assert list(destination.iterdir()) == []


def test_firmware_scan_rejects_oversized_input(tmp_path, monkeypatch):
    firmware_image = tmp_path / "large.bin"
    firmware_image.write_bytes(b"12345")
    monkeypatch.setattr(firmware, "MAX_FIRMWARE_FILE_SIZE_BYTES", 4)

    with pytest.raises(ValueError, match="maximum supported size"):
        scan_firmware_file(str(firmware_image))


def test_invalid_tar_archive_fails_explicitly(tmp_path):
    archive = tmp_path / "invalid.tar"
    archive.write_bytes(b"not a tar archive")

    with pytest.raises(ValueError, match="tar archive is invalid"):
        scan_firmware_file(str(archive))


def test_binwalk_extraction_is_confined_to_temporary_destination(tmp_path, monkeypatch):
    firmware_image = tmp_path / "firmware.bin"
    firmware_image.write_bytes(b"image")
    destination = tmp_path / "extract"
    destination.mkdir()
    commands = []

    monkeypatch.setattr(firmware.shutil, "which", lambda _name: "/usr/bin/binwalk")
    monkeypatch.setattr(
        firmware,
        "_run_limited_extractor",
        lambda command, _destination: commands.append(command),
    )
    firmware._extract_binwalk_image(firmware_image, destination)

    assert commands[0][0] == "/usr/bin/binwalk"
    assert commands[0][commands[0].index("-C") + 1] == str(destination)
    assert not (tmp_path / "firmware.bin_extracted").exists()


def test_extracted_tree_limits_directory_entries(tmp_path, monkeypatch):
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "file.bin").write_bytes(b"safe")
    monkeypatch.setattr(firmware, "MAX_ARCHIVE_MEMBERS", 1)

    with pytest.raises(ValueError, match="too many entries"):
        firmware._validate_extracted_tree(tmp_path)


def test_strings_output_is_streamed_and_capped(tmp_path, monkeypatch):
    image = tmp_path / "large.bin"
    image.write_bytes(b"firmware")
    pid_file = tmp_path / "strings.pid"
    strings = _write_executable(
        tmp_path / "strings",
        "import os, sys\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "line = b'0 ' + b'x' * 512 + b'\\n'\n"
        "while True:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(strings) if name == "strings" else None,
    )
    monkeypatch.setattr(firmware, "MAX_STRINGS_OUTPUT_BYTES", 4096)

    with pytest.raises(ValueError, match="strings output exceeds"):
        list(firmware._extract_strings(image))

    _assert_process_stopped(int(pid_file.read_text(encoding="utf-8")))


def test_firmware_result_limit_stops_strings_subprocess(tmp_path, monkeypatch):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    pid_file = tmp_path / "strings.pid"
    strings = _write_executable(
        tmp_path / "strings",
        "import os, sys\n"
        f"open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
        "line = b'0 password=secretvalue api_key=abcdefghijklmnop\\n'\n"
        "while True:\n"
        "    sys.stdout.buffer.write(line)\n"
        "    sys.stdout.buffer.flush()\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(strings) if name == "strings" else None,
    )
    monkeypatch.setattr(firmware, "MAX_FIRMWARE_FINDINGS_PER_FILE", 1)

    with pytest.raises(ValueError, match="too many security findings"):
        scan_firmware_file(str(image))

    _assert_process_stopped(int(pid_file.read_text(encoding="utf-8")))


def test_fallback_string_scan_reads_in_chunks_and_preserves_detection(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"\x00password=secret-device-password\x00")
    monkeypatch.setattr(firmware.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda _self: pytest.fail("fallback must not load the complete file"),
    )

    strings = list(firmware._extract_strings(image))

    assert strings == [(1, "password=secret-device-password")]


def test_firmware_results_are_bounded_per_file_and_across_the_scan(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    monkeypatch.setattr(firmware.shutil, "which", lambda _name: None)
    monkeypatch.setattr(
        firmware,
        "_extract_strings",
        lambda _path: iter([(0, "password=" + "x" * 5000)]),
    )

    findings = scan_firmware_file(str(image))

    assert len(findings) == 1
    assert len(findings[0]["match"]) == firmware.MAX_FINDING_MATCH_CHARS

    monkeypatch.setattr(
        firmware,
        "_extract_strings",
        lambda _path: iter(
            [
                (0, "password=secretvalue api_key=abcdefghijklmnop"),
            ]
        ),
    )
    monkeypatch.setattr(firmware, "MAX_FIRMWARE_FINDINGS_PER_FILE", 1)

    with pytest.raises(ValueError, match="too many security findings"):
        scan_firmware_file(str(image))

    monkeypatch.setattr(firmware, "MAX_FIRMWARE_FINDINGS_PER_FILE", 10)
    monkeypatch.setattr(firmware, "MAX_FIRMWARE_FINDINGS", 1)
    monkeypatch.setattr(
        firmware,
        "_extract_strings",
        lambda _path: iter(
            [
                (0, "password=secretvalue"),
                (40, "token=abcdefghijklmnop"),
            ]
        ),
    )

    with pytest.raises(ValueError, match="too many security findings"):
        scan_firmware_file(str(image))


def test_external_extraction_is_bounded_by_sandbox_filesystem(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import sys\n"
        "from pathlib import Path\n"
        "destination = sys.argv[sys.argv.index('-C') + 1]\n"
        "(Path(destination) / 'oversized.bin').write_bytes(b'x' * 131072)\n",
    )
    monkeypatch.setattr(
        firmware,
        "MAX_EXTRACTED_TOTAL_SIZE_BYTES",
        32 * 1024,
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )
    temporary_directories = _track_temporary_directories(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="firmware extraction failed"):
        scan_firmware_file(str(image))

    _assert_temporary_directories_removed(temporary_directories)


def test_external_extraction_skips_when_bubblewrap_is_unavailable(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "from pathlib import Path\n"
        f"Path({str(tmp_path / 'executed')!r}).touch()\n",
    )
    monkeypatch.setattr(firmware, "_BWRAP_EXECUTABLE", None)
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )

    with pytest.warns(RuntimeWarning, match="bubblewrap is unavailable"):
        findings = scan_firmware_file(str(image))

    assert findings == []
    assert not (tmp_path / "executed").exists()


def test_external_extraction_preserves_secret_detection(tmp_path, monkeypatch):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import sys\n"
        "from pathlib import Path\n"
        "destination = sys.argv[sys.argv.index('-C') + 1]\n"
        "(Path(destination) / 'device.conf').write_text("
        "'password=secret-device-password', encoding='utf-8')\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )

    findings = scan_firmware_file(str(image))

    assert any(
        finding["type"] == "hardcoded_password"
        and Path(finding["file"]).name == "device.conf"
        for finding in findings
    )


@pytest.mark.parametrize(
    ("limit_name", "limit", "source", "message"),
    [
        (
            "MAX_EXTRACTED_TOTAL_SIZE_BYTES",
            32 * 1024,
            (
                "with open(Path(destination) / 'expanded.bin', 'wb', buffering=0) as f:\n"
                "    while True:\n"
                "        f.write(b'x' * 1024)\n"
                "        time.sleep(0.005)\n"
            ),
            "firmware extraction failed|exceeds the supported size",
        ),
        (
            "MAX_ARCHIVE_MEMBERS",
            4,
            (
                "for index in range(1000):\n"
                "    (Path(destination) / str(index)).write_bytes(b'x')\n"
                "    time.sleep(0.005)\n"
            ),
            "too many entries",
        ),
    ],
)
def test_external_extraction_enforces_limits_live_and_cleans_temp_directory(
    tmp_path, monkeypatch, limit_name, limit, source, message
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    pid_file = tmp_path / "extractor.pid"
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import os, sys, time\n"
        "from pathlib import Path\n"
        "destination = sys.argv[sys.argv.index('-C') + 1]\n"
        + source,
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )
    monkeypatch.setattr(firmware, limit_name, limit)
    monkeypatch.setattr(firmware, "EXTRACTION_MONITOR_INTERVAL_SECONDS", 0.01)
    temporary_directories = _track_temporary_directories(monkeypatch, tmp_path)
    _track_extractor_process(monkeypatch, pid_file)

    with pytest.raises((ValueError, RuntimeError), match=message):
        scan_firmware_file(str(image))

    _assert_process_stopped(int(pid_file.read_text(encoding="utf-8")))
    _assert_temporary_directories_removed(temporary_directories)


def test_external_extractor_timeout_kills_process_and_cleans_temp_directory(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    pid_file = tmp_path / "extractor.pid"
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import os, sys, time\n"
        "time.sleep(30)\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )
    monkeypatch.setattr(firmware, "EXTRACTION_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(firmware, "EXTRACTION_MONITOR_INTERVAL_SECONDS", 0.01)
    temporary_directories = _track_temporary_directories(monkeypatch, tmp_path)
    _track_extractor_process(monkeypatch, pid_file)

    with pytest.raises(RuntimeError, match="extraction timed out"):
        scan_firmware_file(str(image))

    _assert_process_stopped(int(pid_file.read_text(encoding="utf-8")))
    _assert_temporary_directories_removed(temporary_directories)


def test_external_extractor_failure_cleans_temp_directory(tmp_path, monkeypatch):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import sys\n"
        "sys.exit(7)\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )
    temporary_directories = _track_temporary_directories(monkeypatch, tmp_path)

    with pytest.raises(RuntimeError, match="firmware extraction failed"):
        scan_firmware_file(str(image))

    _assert_temporary_directories_removed(temporary_directories)


def test_interrupted_external_extraction_kills_process_and_cleans_temp_directory(
    tmp_path, monkeypatch
):
    image = tmp_path / "firmware.bin"
    image.write_bytes(b"firmware")
    pid_file = tmp_path / "extractor.pid"
    binwalk = _write_executable(
        tmp_path / "binwalk",
        "import os, sys, time\n"
        "time.sleep(30)\n",
    )
    monkeypatch.setattr(
        firmware.shutil,
        "which",
        lambda name: str(binwalk) if name == "binwalk" else None,
    )
    temporary_directories = _track_temporary_directories(monkeypatch, tmp_path)
    _track_extractor_process(monkeypatch, pid_file)

    def interrupt_when_started(_destination):
        deadline = time.monotonic() + 2
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
        raise KeyboardInterrupt

    monkeypatch.setattr(firmware, "_validate_extracted_tree", interrupt_when_started)

    with pytest.raises(KeyboardInterrupt):
        scan_firmware_file(str(image))

    _assert_process_stopped(int(pid_file.read_text(encoding="utf-8")))
    _assert_temporary_directories_removed(temporary_directories)
