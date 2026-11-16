"""Verify driver-free I/O against native captures and independent format fixtures."""
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from packetscope import capture


def block(order, kind, body):
    length = len(body) + 12
    return struct.pack(order + 'II', kind, length) + body + struct.pack(order + 'I', length)


def section(order):
    return block(order, 0x0a0d0d0a, struct.pack(order + 'IHHq', 0x1a2b3c4d, 1, 0, -1))


def interface(order, resolution=6, offset=0):
    options = struct.pack(order + 'HHB3xHHqHH', 9, 1, resolution, 14, 8, offset, 0, 0)
    return block(order, 1, struct.pack(order + 'HHI', 1, 0, 65535) + options)


def packet(order, index, ticks):
    return block(order, 6, struct.pack(order + '5I', index, ticks >> 32, ticks & 0xffffffff, 3, 50)
                 + b'xyz\0')


class PortableCaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / '离线 抓包.pcap'
        self.missing = patch.object(capture, '_library', side_effect=capture.CaptureError('无抓包库'))

    def load(self, data):
        self.path.write_bytes(data)
        with self.missing:
            return list(capture.read_file(self.path))

    def test_all_classic_magic_numbers_truncated_frames(self):
        for order in ('<', '>'):
            for magic, units in ((0xa1b2c3d4, 10**6), (0xa1b23c4d, 10**9)):
                with self.subTest(order=order, units=units):
                    header = struct.pack(order + 'IHHIIII', magic, 2, 4, 0, 0, 80, 101)
                    rec = struct.pack(order + '4I', 17, 555, 4, 95) + b'data'
                    self.assertEqual(self.load(header + rec),
                                     [capture.Frame(17 + 555 / units, b'data', 95, 12)])
                    with self.assertRaisesRegex(capture.CaptureError, '截断'):
                        self.load(header + rec[:-1])

    def test_ng_time_resolution_interfaces_and_new_sections(self):
        first = (section('<') + interface('<', 9, -4) + interface('<', 0x8a, 10)
                 + block('<', 4, bytes(4)) + packet('<', 0, 5_000_000_011) + packet('<', 1, 1025))
        second = section('>') + interface('>') + packet('>', 0, 56_000)
        frames = self.load(first + second)
        self.assertEqual([f.data for f in frames], [b'xyz'] * 3)
        for f, t in zip(frames, [1.000000011, 11 + 1 / 1024, .056]):
            self.assertAlmostEqual(f.timestamp, t, places=10)

    def test_ng_rejects_unreadable_records(self):
        head = section('<') + interface('<')
        unknown_interface = packet('<', 1, 0)
        unsupported_simple = block('<', 3, struct.pack('<I', 3) + b'abc\0')
        wrong_end = packet('<', 0, 0)[:-4] + bytes(4)
        oversized = struct.pack('<II', 6, 0xfffffff0)
        for record in (unknown_interface, unsupported_simple, wrong_end, oversized):
            with self.subTest(record=record):
                with self.assertRaises(capture.CaptureError):
                    self.load(head + record)

    def test_export_atomic_and_readable_by_native_reader(self):
        example = Path(__file__).resolve().parents[1] / 'examples' / 'loopback-demo.pcap'
        native_or_portable = list(capture.read_file(example))
        self.assertGreater(len(native_or_portable), 1)
        with self.missing:
            records = list(capture.read_file(example))
            self.assertEqual(records, native_or_portable)
            capture.save_file(self.path, iter(records))
            before = self.path.read_bytes()
            with self.assertRaisesRegex(capture.CaptureError, '链路类型'):
                capture.save_file(self.path, [records[0], capture.Frame(1, b'x', 1, 1)])
            self.assertEqual(self.path.read_bytes(), before)
            self.assertEqual(list(self.path.parent.iterdir()), [self.path])
        self.assertEqual(list(capture.read_file(self.path)), records)
