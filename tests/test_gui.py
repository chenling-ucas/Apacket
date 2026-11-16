"""Exercise the same selection, filter and details panes used in the desktop app."""

import os
import socket
import struct
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtWidgets import QApplication
from packetscope.capture import Frame, read_file
from packetscope.gui import Window
from packetscope.session import Session, display_predicate


def dns_frame(response=False):
    question = b"\x04demo\x05local\x00" + struct.pack("!HH", 1, 1)
    message = (
        struct.pack("!6H", 23, 0x8180 if response else 0x0100, 1, 0, 0, 0) + question
    )
    src, dst = ("10.0.0.1", "10.0.0.2") if response else ("10.0.0.2", "10.0.0.1")
    ports = (53, 50000) if response else (50000, 53)
    udp = struct.pack("!4H", *ports, len(message) + 8, 0) + message
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        0,
        0,
        64,
        17,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    data = bytes(12) + b"\x08\x00" + ip + udp
    return Frame(1.02 if response else 1, data, len(data), 1)


class DesktopTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.w = Window()
        self.w.pulse.stop()

    def tearDown(self):
        self.w.unsaved = False
        self.w.close()

    def test_live_dns_response_updates_selected_query_and_jump(self):
        self.w.events.put(("batch", [dns_frame()]))
        self.w.poll()
        self.w.select_number(1)
        layer = self.w.tree.topLevelItem(1)
        self.w.tree.setCurrentItem(layer.child(0))
        self.w.events.put(("batch", [dns_frame(True)]))
        self.w.poll()
        root = self.w.tree.topLevelItem(0)
        link = next(
            root.child(i)
            for i in range(root.childCount())
            if "配对" in root.child(i).text(0)
        )
        self.assertIn("#2", link.text(1))
        self.assertIn("20.000 ms", link.text(1))
        self.assertTrue(self.w.hex.extraSelections())
        self.w.follow_peer(link, 0)
        self.assertEqual(self.w.selected.number, 2)

    def test_process_filter_matches_either_endpoint_and_invalid_rule_preserves_view(
        self,
    ):
        s = Session()
        for frame in read_file(
            Path(__file__).resolve().parents[1] / "examples" / "loopback-demo.pcap"
        ):
            s.append(frame)
        stream = s.analysis.streams[0]
        s.owners[stream.id] = {
            stream.left: "curl (PID 7)",
            stream.right: "Python (PID 9)",
        }
        self.w.install(s)
        self.w.set_filter('process == "curl (PID 7)"')
        self.assertEqual(self.w.proxy.rowCount(), len(stream.frames))
        self.w.set_filter("tcp.port ==")
        self.assertEqual(self.w.proxy.rowCount(), len(stream.frames))
        self.assertFalse(self.w.filter_msg.isHidden())
        self.w.set_filter("http and (tcp or udp)")
        self.assertGreater(self.w.proxy.rowCount(), 0)
        self.w.select_number(stream.frames[0])
        self.assertEqual(self.w.selected.number, stream.frames[0])
