"""Read local TCP endpoints and their owning PIDs from Windows IP Helper."""
from __future__ import annotations

import ctypes
import ipaddress
import ntpath
import socket
from functools import lru_cache

from .analysis import Connection, Endpoint


_DWORD = ctypes.c_uint32
_PDWORD = ctypes.POINTER(_DWORD)
_AF_INET, _AF_INET6 = 2, 23  # Winsock address family values
_TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_NOT_SUPPORTED = 50
_WSAEAFNOSUPPORT = 10047
_ERROR_NO_DATA = 232
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class _TcpRow(ctypes.Structure):
    """MIB_TCPROW_OWNER_PID. Address bytes are already in network order."""

    _fields_ = [
        ('state', _DWORD),
        ('local_address', ctypes.c_ubyte * 4),
        ('local_port', _DWORD),
        ('remote_address', ctypes.c_ubyte * 4),
        ('remote_port', _DWORD),
        ('pid', _DWORD),
    ]


class _Tcp6Row(ctypes.Structure):
    """MIB_TCP6ROW_OWNER_PID. Scope IDs are separate from the IPv6 addresses."""

    _fields_ = [
        ('local_address', ctypes.c_ubyte * 16),
        ('local_scope', _DWORD),
        ('local_port', _DWORD),
        ('remote_address', ctypes.c_ubyte * 16),
        ('remote_scope', _DWORD),
        ('remote_port', _DWORD),
        ('state', _DWORD),
        ('pid', _DWORD),
    ]


@lru_cache(maxsize=1)
def _api():
    # LOAD_LIBRARY_SEARCH_SYSTEM32 selects the Windows system DLLs by name.
    iphelper = ctypes.WinDLL('iphlpapi.dll', winmode=0x800)
    kernel32 = ctypes.WinDLL('kernel32.dll', winmode=0x800)
    iphelper.GetExtendedTcpTable.argtypes = [
        ctypes.c_void_p, _PDWORD, ctypes.c_int, _DWORD, ctypes.c_int, _DWORD,
    ]
    iphelper.GetExtendedTcpTable.restype = _DWORD
    kernel32.OpenProcess.argtypes = [_DWORD, ctypes.c_int, _DWORD]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p, _DWORD, ctypes.POINTER(ctypes.c_wchar), _PDWORD,
    ]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    return iphelper, kernel32


def _read_rows(get_table, family, row_type):
    """Return the table rows, or None if the address family is unavailable."""
    size = _DWORD()
    buffer = None
    for _ in range(6):
        status = get_table(buffer, ctypes.byref(size), False, family, _TCP_TABLE_OWNER_PID_ALL, 0)
        if status == _ERROR_INSUFFICIENT_BUFFER:
            # Connections can appear between the size probe and the next call.
            if buffer is not None:
                size.value += 32 * ctypes.sizeof(row_type)
            buffer = ctypes.create_string_buffer(size.value)
            continue
        if status in (_ERROR_NOT_SUPPORTED, _WSAEAFNOSUPPORT):
            return None
        if status == _ERROR_NO_DATA:
            return ()
        if status:
            raise OSError(f'读取 Windows TCP 连接表失败（错误码 {status}）')
        header = ctypes.sizeof(_DWORD)
        available = min(len(buffer), size.value) if buffer is not None else 0
        if available < header:
            raise RuntimeError('Windows TCP 连接表缺少表头。')
        count = _DWORD.from_buffer(buffer).value
        if count * ctypes.sizeof(row_type) > available - header:
            raise RuntimeError('Windows TCP 连接表长度不足。')
        return (row_type * count).from_buffer(buffer, header)
    raise RuntimeError('Windows TCP 连接表持续增长，本次采样未完成。')


def _endpoint(raw_address, raw_port: int) -> Endpoint | None:
    address = ipaddress.ip_address(bytes(raw_address))
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    port = socket.ntohs(raw_port & 0xffff)
    if not port or address.is_unspecified:
        return None
    return str(address), port


def _process_label(kernel32, pid: int) -> str:
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if handle:
        try:
            path = ctypes.create_unicode_buffer(32768)
            size = _DWORD(len(path))
            if kernel32.QueryFullProcessImageNameW(handle, 0, path, ctypes.byref(size)):
                name = ntpath.basename(path.value)
                if name:
                    return f'{name} (PID {pid})'
        finally:
            kernel32.CloseHandle(handle)
    return f'PID {pid}'


def snapshot() -> dict[Connection, str]:
    """Map each observed TCP connection to its local process for this sample."""
    iphelper, kernel32 = _api()
    pids: dict[Connection, int] = {}
    available = False
    for family, row_type in ((_AF_INET, _TcpRow), (_AF_INET6, _Tcp6Row)):
        rows = _read_rows(iphelper.GetExtendedTcpTable, family, row_type)
        if rows is None:
            continue
        available = True
        for row in rows:
            if not row.pid or row.state in (1, 2, 12):  # CLOSED, LISTEN, DELETE_TCB
                continue
            local = _endpoint(row.local_address, row.local_port)
            peer = _endpoint(row.remote_address, row.remote_port)
            if local and peer:
                connection = (local, peer)
                # Capture addresses have no IPv6 scope ID. Leave ambiguous tuples unassigned.
                if pids.setdefault(connection, row.pid) != row.pid:
                    pids[connection] = 0
    if not available:
        raise RuntimeError('Windows 无法提供 IPv4 或 IPv6 的 TCP 进程表。')

    names = {pid: _process_label(kernel32, pid) for pid in set(pids.values()) if pid}
    return {connection: names[pid] for connection, pid in pids.items() if pid}
