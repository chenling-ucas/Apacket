"""Use synthetic captures so regression tests never need capture privileges."""
import struct
import tempfile
import unittest
from pathlib import Path

from packetscope.capture import CaptureError, Frame, read_file, save_file


def block(kind, payload):
    length = 12 + len(payload)
    return struct.pack('<II', kind, length) + payload + struct.pack('<I', length)


class CaptureTests(unittest.TestCase):
    def test_native_roundtrip_preserves_truncated_frame(self):
        records = [
            Frame(1779000000.345678, b'\xff' * 60, 1500, 1),
            Frame(1779000001.456789, b'\x00' * 64, 64, 1),
        ]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / '有空格 的抓包.pcap'
            save_file(target, records)
            self.assertEqual(list(read_file(target)), records)

    def test_export_failure_preserves_existing_file(self):
        frames = [Frame(1, b'A', 1, 1), Frame(2, b'B', 1, 0)]
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'good.pcap'
            target.write_bytes(b'original file')
            with self.assertRaisesRegex(CaptureError, '链路类型'):
                save_file(target, iter(frames))
            self.assertEqual(target.read_bytes(), b'original file')
            self.assertEqual(list(target.parent.iterdir()), [target])

    def test_corrupt_and_mixed_interface_captures_raise(self):
        # One section, two interfaces using different link-layer formats.
        shb = block(0x0a0d0d0a, struct.pack('<IHHq', 0x1a2b3c4d, 1, 0, -1))
        eth = block(1, struct.pack('<HHI', 1, 0, 65535))
        loopback = block(1, struct.pack('<HHI', 0, 0, 65535))
        packet = block(6, struct.pack('<IIIII', 1, 0, 0, 4, 4) + b'\0' * 4)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.pcapng'
            for sample in (shb + eth + loopback + packet, b'incomplete'):
                with self.subTest(size=len(sample)):
                    path.write_bytes(sample)
                    with self.assertRaises(CaptureError):
                        list(read_file(path))


if __name__ == '__main__':
    unittest.main()
