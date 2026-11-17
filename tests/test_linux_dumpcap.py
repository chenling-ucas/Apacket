"""Check local interface restrictions, process cleanup, and the streamed PCAP path."""
import ctypes
import errno
import struct
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

from apacket import capture, linux_dumpcap


@unittest.skipIf(sys.platform == 'win32', 'Linux helper uses Unix subprocess pipes')
class LinuxDumpcapTests(unittest.TestCase):
    def helper_process(self, code):
        spawn = subprocess.Popen
        seen = []

        def substitute(args, **kwargs):
            proc = spawn([sys.executable, '-c', code], **kwargs)
            seen.append((args, proc))
            return proc

        self.enter_patch(patch.object(linux_dumpcap.subprocess, 'Popen', substitute))
        self.enter_patch(patch.object(linux_dumpcap.socket, 'if_nameindex', return_value=[(1, 'lo')]))
        return seen

    def enter_patch(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def next_frame(source):
        until = time.monotonic() + 4
        while time.monotonic() < until:
            frame = source.read()
            if frame is not None:
                return frame
            time.sleep(.01)
        raise AssertionError('等待 helper 输出超时')

    def test_permission_error_streams_real_pipe_without_spooling(self):
        header = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        record = struct.pack('<4I', 10, 250_000, 3, 300) + b'abc'
        seen = self.helper_process(
            'import sys, time\n'
            "sys.stderr.buffer.write(b'x' * 70000); sys.stderr.flush()\n"
            f'sys.stdout.buffer.write({header!r}); sys.stdout.flush()\n'
            f'sys.stdout.buffer.write({record!r} * 2000); sys.stdout.flush()\n'
            'time.sleep(30)'
        )
        lib = Mock()

        def denied(*args):
            ctypes.set_errno(errno.EPERM)
            return None

        lib.pcap_open_live.side_effect = denied
        with patch.object(capture.sys, 'platform', 'linux'), patch.object(capture, '_library', return_value=lib):
            with capture.open_live('lo', 'tcp port 8000') as source:
                self.assertEqual(self.next_frame(source), capture.Frame(10.25, b'abc', 300, 1))
        args, proc = seen[0]
        self.assertEqual(args, ['/usr/bin/dumpcap', '-q', '-p', '-P', '-s', '262144',
                                '-i', 'lo', '-f', 'tcp port 8000', '-w', '-'])
        self.assertIsNotNone(proc.poll())
        self.assertTrue(proc.stderr.closed and proc.stdout.closed)

    def test_no_remote_pipe_or_filename(self):
        with patch.object(linux_dumpcap.socket, 'if_nameindex', return_value=[(1, 'lo')]), \
                patch.object(linux_dumpcap.subprocess, 'Popen') as spawn:
            for name in ('TCP@example.test:443', 'rpcap://host/eth0', '-', '/tmp/example.pcap', '1'):
                with self.subTest(name=name), self.assertRaisesRegex(capture.CaptureError, '本机'):
                    linux_dumpcap.DumpcapCapture(name, '')
            spawn.assert_not_called()

    def test_startup_error_reaches_user_and_reaps_child(self):
        seen = self.helper_process('import sys; sys.stderr.write("Permission denied"); sys.exit(1)')
        with linux_dumpcap.DumpcapCapture('any', '') as source:
            with self.assertRaisesRegex(capture.CaptureError, 'wireshark 组'):
                self.next_frame(source)
        self.assertEqual(seen[0][1].poll(), 1)
