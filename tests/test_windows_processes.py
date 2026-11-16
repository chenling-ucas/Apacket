"""Exercise Windows OWNER_PID table bytes independently of the host's C layouts."""

import ctypes as C
import ipaddress
import struct
import unittest
from unittest.mock import Mock, patch

from packetscope import windows_processes


def tcp_row(local, peer, pid, state=5, scope=0):
    def endpoint(pair):
        address = ipaddress.ip_address(pair[0]).packed
        port = struct.pack('!H', pair[1]) + bytes(2)
        if len(address) == 16:
            return address + struct.pack('<I', scope) + port
        return address + port

    endpoints = endpoint(local) + endpoint(peer)
    if ':' in local[0]:
        return endpoints + struct.pack('<II', state, pid)
    return struct.pack('<I', state) + endpoints + struct.pack('<I', pid)


class TableAPI:
    def __init__(self, ipv4=(), ipv6=()):
        self.tables = {2: ipv4, 23: ipv6}
        self.resized = set()

    def GetExtendedTcpTable(self, buffer, size_ptr, ordered, family, table_class, reserved):
        rows = self.tables[family]
        if isinstance(rows, int):
            return rows
        data = struct.pack('<I', len(rows)) + b''.join(rows)
        size = C.cast(size_ptr, C.POINTER(C.c_uint32))
        if not buffer:
            # Only the header fit when the size was first measured.
            size[0] = 4
            return 122  # ERROR_INSUFFICIENT_BUFFER
        if size[0] < len(data):
            self.resized.add(family)
            size[0] = len(data)
            return 122
        C.memmove(buffer, data, len(data))
        size[0] = len(data)
        return 0


def kernel_api():
    kernel = Mock()
    kernel.OpenProcess.side_effect = lambda access, inherit, pid: pid if pid == 41 else None

    def read_image(handle, flags, buffer, size_ptr):
        path = r'C:\应用\Browser.exe'
        buffer.value = path
        C.cast(size_ptr, C.POINTER(C.c_uint32))[0] = len(path)
        return 1

    kernel.QueryFullProcessImageNameW.side_effect = read_image
    return kernel


class WindowsTableTests(unittest.TestCase):
    def test_resized_tables_yield_oriented_owners_and_pid_only_fallback(self):
        v4 = ('192.0.2.7', 51234), ('198.51.100.29', 443)
        v6 = ('fe80::12ab', 43123), ('fe80::26cd', 8443)
        tables = TableAPI(
            ipv4=[tcp_row(*v4, 41), tcp_row(*v4[::-1], 73),
                  tcp_row(('0.0.0.0', 9999), ('0.0.0.0', 0), 88, state=2),
                  tcp_row(('192.0.2.18', 41555), v4[1], 88, state=1),
                  tcp_row(('192.0.2.19', 41111), v4[1], 0)],
            ipv6=[tcp_row(*v6, 41, scope=17)],
        )
        kernel = kernel_api()
        with patch.object(windows_processes, '_api', return_value=(tables, kernel)):
            owners = windows_processes.snapshot()
        self.assertEqual(owners, {
            v4: 'Browser.exe (PID 41)', v4[::-1]: 'PID 73', v6: 'Browser.exe (PID 41)',
        })
        self.assertEqual(tables.resized, {2, 23})
        kernel.CloseHandle.assert_called_once_with(41)

    def test_mapped_ipv4_with_ipv6_only_table_and_ambiguous_scope(self):
        v4 = ('192.0.2.7', 53191), ('198.51.100.2', 80)
        mapped = tuple(('::ffff:' + host, port) for host, port in v4)
        link_local = ('fe80::1', 49153), ('fe80::2', 443)
        tables = TableAPI(ipv4=50, ipv6=[
            tcp_row(*mapped, 41),
            tcp_row(*link_local, 41, scope=7),
            tcp_row(*link_local, 73, scope=11),
        ])
        with patch.object(windows_processes, '_api', return_value=(tables, kernel_api())):
            self.assertEqual(windows_processes.snapshot(), {v4: 'Browser.exe (PID 41)'})

    def test_image_query_failure_keeps_pid_and_releases_handle(self):
        endpoints = ('192.0.2.7', 49153), ('192.0.2.8', 80)
        tables = TableAPI(ipv4=[tcp_row(*endpoints, 41)])
        kernel = kernel_api()
        kernel.QueryFullProcessImageNameW.side_effect = None
        kernel.QueryFullProcessImageNameW.return_value = 0
        with patch.object(windows_processes, '_api', return_value=(tables, kernel)):
            self.assertEqual(windows_processes.snapshot(), {endpoints: 'PID 41'})
        kernel.CloseHandle.assert_called_once_with(41)
