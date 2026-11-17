"""Build the shareable desktop ZIP from the working tree, including new files."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DEFAULT = ROOT / "交付" / "Apacket-Desktop.zip"


def contents() -> list[str]:
    files = {
        "README.md", "LICENSE", "requirements.txt", "Start-Apacket.cmd",
        "bootstrap-windows.ps1", "启动 Apacket.command", "Start-Apacket-Linux.sh",
        "bootstrap/start-posix.sh", "bootstrap/linux-desktop.sh", "bootstrap/macos-capture.sh",
        "tools/build_release.py",
        "examples/loopback-demo.pcap", "experiments/local_demo.py", "experiments/acceptance.py",
    }
    guide = "docs/Apacket从零读懂抓包与协议分析.pdf"
    if (ROOT / guide).is_file():
        files.add(guide)
    for directory in ("apacket", "tests"):
        files.update(p.relative_to(ROOT).as_posix() for p in (ROOT / directory).glob("*.py"))
    return sorted(files)


def build(target: Path) -> str:
    target = target.resolve()
    if target.suffix.lower() != ".zip":
        raise ValueError("发行文件需要使用 .zip 扩展名")
    target.parent.mkdir(parents=True, exist_ok=True)
    # Stage beside the destination so a cancelled build preserves the previous ZIP.
    fd, temp_name = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    os.close(fd)
    tmp = Path(temp_name)
    try:
        names = contents()
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name in names:
                source = ROOT / name
                if source.is_symlink() or not source.is_file():
                    raise ValueError(f"发行文件缺失或不是普通文件：{name}")
                entry = zipfile.ZipInfo("Apacket/" + name, (2026, 1, 1, 0, 0, 0))
                entry.create_system = 3
                mode = 0o755 if name.endswith((".command", ".sh")) else 0o644
                entry.external_attr = (0o100000 | mode) << 16
                data = source.read_bytes()
                if name.endswith((".cmd", ".ps1")):
                    data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
                archive.writestr(entry, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        with zipfile.ZipFile(tmp) as archive:
            if archive.testzip() is not None:
                raise ValueError("ZIP 校验失败")
        digest = hashlib.sha256(tmp.read_bytes()).hexdigest()
        tmp.chmod(0o644)
        os.replace(tmp, target)
    finally:
        tmp.unlink(missing_ok=True)
    return digest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="生成可分发的 Apacket 桌面 ZIP")
    parser.add_argument("target", type=Path, nargs="?", default=DEFAULT)
    path = parser.parse_args().target
    print(f"{build(path)}  {path}")
