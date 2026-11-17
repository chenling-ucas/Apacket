"""Read local TCP socket ownership from Windows IP Helper or POSIX lsof."""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
import sys

from .analysis import Connection, Endpoint


def _endpoint(text: str) -> Endpoint | None:
    host, colon, port = text.rpartition(':')
    if not colon or not port.isdigit():
        return None
    host = host.strip('[]').split('%', 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped:
            address = address.ipv4_mapped
        elif sys.platform == 'darwin' and address.is_link_local:
            # Darwin lsof can embed the interface index in bits 16..31.
            packed = bytearray(address.packed)
            packed[2:4] = b'\x00\x00'
            address = ipaddress.IPv6Address(bytes(packed))
    return str(address), int(port)


def _parse_lsof(output: str) -> dict[Connection, str]:
    result = {}
    pid = command = ''
    for line in output.splitlines():
        kind, value = line[:1], line[1:]
        if kind == 'p':
            pid, command = value, ''
        elif kind == 'c':
            command = value
        elif kind == 'n' and pid and command and '->' in value:
            local, peer = map(_endpoint, value.split('->', 1))
            if local and peer:
                result[(local, peer)] = f'{command} (PID {pid})'
    return result


def snapshot() -> dict[Connection, str]:
    """Map (local endpoint, remote endpoint) to observed process; call off the UI thread."""
    if sys.platform == 'win32':
        from .windows_processes import snapshot as windows_snapshot
        return windows_snapshot()

    exe = shutil.which('lsof')
    if not exe:
        raise RuntimeError('系统缺少 lsof，无法采样 TCP 进程。')
    try:
        proc = subprocess.run([exe, '-nP', '+c', '0', '-iTCP', '-Fpcn'],
                              capture_output=True, text=True, errors='replace', timeout=4)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'读取 TCP 进程失败：{exc}') from exc
    if proc.returncode and not proc.stdout.strip() and proc.stderr.strip():
        raise RuntimeError('读取 TCP 进程失败：' + proc.stderr.strip().splitlines()[-1])
    return _parse_lsof(proc.stdout)
