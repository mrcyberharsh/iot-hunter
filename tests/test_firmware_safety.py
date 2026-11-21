import io
import tarfile
from pathlib import Path

from modules.firmware import _extract_tar_archive


def _make_tar(path, entries):
    with tarfile.open(path, "w") as tar:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))


def test_tar_path_traversal_is_blocked(tmp_path):
    archive = tmp_path / "fw.tar"
    _make_tar(archive, {"ok/file.txt": b"hello", "../escaped.txt": b"bad", "/abs.txt": b"bad"})
    dest = tmp_path / "out"
    dest.mkdir()
    _extract_tar_archive(archive, dest)
    assert (dest / "ok" / "file.txt").read_text() == "hello"
    assert not (tmp_path / "escaped.txt").exists()
    assert not Path("/abs.txt").exists()
