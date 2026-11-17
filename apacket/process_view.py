"""Inspect local process ownership alongside the traffic that supports each note."""

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
)

from .note_panel import NotePanel
from .process_teaching import endpoint_note, process_note
from .views import StreamDialog, endpoint


class ProcessDialog(QDialog):
    def __init__(self, session, parent=None):
        super().__init__(parent)
        self.session = session
        self.groups = {}
        self.connections = {}
        self.displayed = None

        self.setWindowTitle("按进程查看 TCP 流")
        self.resize(1060, 590)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 14)
        layout.addWidget(
            QLabel("单击查看进程或连接详情，双击连接打开 TCP 时序图。")
        )
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["本机进程 / TCP 流", "本地端点", "对端"])
        self.tree.setColumnWidth(0, 185)
        self.tree.setColumnWidth(1, 180)
        self.tree.setHorizontalScrollMode(QTreeWidget.ScrollMode.ScrollPerPixel)
        self.panel = NotePanel()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.panel)
        splitter.setSizes([570, 440])
        layout.addWidget(splitter, 1)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        close.rejected.connect(self.reject)
        layout.addWidget(close)

        self.tree.currentItemChanged.connect(self.show_notes)
        self.tree.itemDoubleClicked.connect(self.open_stream)
        self.refresh()
        if session.live:
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh)
            self.finished.connect(self.timer.stop)
            self.timer.start(1200)

    def refresh(self):
        tree = self.tree
        tree.blockSignals(True)
        for sid, endpoints in self.session.owners.items():
            stream = self.session.analysis.streams[sid]
            for local, owner in endpoints.items():
                group = self.groups.get(owner)
                if group is None:
                    group = self.groups[owner] = QTreeWidgetItem(tree, [owner])
                    group.setExpanded(True)
                key = (sid, local)
                item = self.connections.get(key)
                if item is None:
                    peer = stream.right if local == stream.left else stream.left
                    item = QTreeWidgetItem(
                        group, [f"流 #{sid}", endpoint(local), endpoint(peer)]
                    )
                    item.setData(0, Qt.ItemDataRole.UserRole, key)
                    self.connections[key] = item
                elif item.parent() is not group:
                    previous = item.parent()
                    selected = tree.currentItem() is item
                    previous.removeChild(item)
                    group.addChild(item)
                    if selected:
                        tree.setCurrentItem(item)
                    if not previous.childCount():
                        del self.groups[previous.text(0)]
                        tree.takeTopLevelItem(tree.indexOfTopLevelItem(previous))
        if tree.currentItem() is None and tree.topLevelItemCount():
            tree.setCurrentItem(tree.topLevelItem(0))
        tree.blockSignals(False)
        self.show_notes(tree.currentItem())

    def show_notes(self, item, previous=None):
        if item is None:
            return
        group = item.parent()
        streams = self.session.analysis.streams
        if group is None:
            owner = item.text(0)
            owned = [
                item.child(i).data(0, Qt.ItemDataRole.UserRole)
                for i in range(item.childCount())
            ]
            observed = tuple(
                (sid, local, len(streams[sid].frames)) for sid, local in owned
            )
        else:
            owner = group.text(0)
            sid, local = item.data(0, Qt.ItemDataRole.UserRole)
            observed = len(streams[sid].frames)
        current = (item, owner, observed)
        if self.displayed == current:
            return
        # Preserve the reader's position when fresh packets update this same note.
        scroll = self.panel.verticalScrollBar()
        position = scroll.value() if self.displayed and self.displayed[0] is item else 0
        if group is None:
            self.panel.set_notes(
                process_note(self.session, owner), overview_label="所选进程"
            )
        else:
            self.panel.set_notes(
                None,
                endpoint_note(self.session, sid, tuple(local), owner),
                detail_label="所选连接",
            )
        scroll.setValue(position)
        self.displayed = current

    def open_stream(self, item, column):
        key = item.data(0, Qt.ItemDataRole.UserRole)
        if key is not None:
            dialog = StreamDialog(self.session, key[0], self)
            dialog.exec()
            dialog.deleteLater()
