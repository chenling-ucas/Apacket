"""Selection and packet evidence stay in sync across the teaching views."""

import os
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import Qt
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from packetscope.capture import read_file
from packetscope.gui import Window
from packetscope.process_view import ProcessDialog
from packetscope.session import Session
from packetscope.views import StreamDialog


class TeachingViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.session = Session()
        path = Path(__file__).resolve().parents[1] / "examples" / "loopback-demo.pcap"
        for frame in read_file(path):
            self.session.append(frame)
        self.stream = self.session.analysis.streams[0]

    def test_trace_opens_on_main_selection_then_follows_arrows_and_table(self):
        selected = self.stream.frames[2]
        main = Window()
        self.addCleanup(main.close)
        main.install(self.session)
        main.select_number(selected)

        def inspect(dialog):
            dialog.show()
            self.app.processEvents()
            self.assertEqual(dialog.selected_frame, selected)
            self.assertIn("握手", dialog.panel.detail.title.text())
            point = dialog.graph.mapFromScene(dialog.graph.row_rect(0).center())
            QTest.mouseClick(
                dialog.graph.viewport(), Qt.MouseButton.LeftButton, pos=point
            )
            self.assertEqual(dialog.selected_frame, self.stream.frames[0])
            self.assertIn("SYN", dialog.panel.detail.title.text())
            QTest.keyClick(dialog.graph, Qt.Key.Key_Down)
            self.assertEqual(dialog.table.currentRow(), 1)
            dialog.tabs.setCurrentWidget(dialog.table)
            QTest.keyClick(dialog.table, Qt.Key.Key_Down)
            self.assertEqual(dialog.graph.current_row, 2)
            self.assertIn(f"#{selected}", dialog.panel.detail.evidence.text())
            dialog.close()

        with patch.object(StreamDialog, "exec", inspect):
            main.trace()

    def test_process_selection_and_new_socket_ownership(self):
        owner = "Client (PID 41)"
        sid, local = self.stream.id, self.stream.left
        self.session.owners[sid] = {local: owner}
        dialog = ProcessDialog(self.session)
        self.addCleanup(dialog.close)
        dialog.show()
        self.app.processEvents()
        group = dialog.tree.currentItem()
        self.assertIn(owner, dialog.panel.overview.title.text())
        self.assertTrue(dialog.panel.detail.isHidden())
        endpoint = group.child(0)
        dialog.tree.setCurrentItem(endpoint)
        self.assertIn(f"流 #{sid}", dialog.panel.detail.title.text())
        self.assertIn(str(local[1]), dialog.panel.detail.explanation.text())
        evidence = dialog.panel.detail.evidence.text()
        self.assertIn("帧", evidence)
        self.session.owners[sid][self.stream.right] = "Server (PID 42)"
        dialog.refresh()
        self.assertIs(dialog.tree.currentItem(), endpoint)
        self.assertEqual(dialog.tree.topLevelItemCount(), 2)
        self.assertEqual(dialog.panel.detail.evidence.text(), evidence)
        peer = dialog.tree.topLevelItem(1).child(0)
        dialog.tree.setCurrentItem(peer)
        self.assertIn("Server (PID 42)", dialog.panel.detail.title.text())
        followed = []
        with patch.object(
            StreamDialog, "exec", lambda flow: followed.append(flow.frames)
        ):
            dialog.tree.itemDoubleClicked.emit(peer, 0)
        self.assertEqual(followed, [self.stream.frames])
