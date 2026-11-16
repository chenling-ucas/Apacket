from __future__ import annotations
from collections import deque
from pathlib import Path
from queue import Queue, Empty
from threading import Event, Thread
import time

from PySide6.QtCore import (
    Qt,
    QTimer,
    QAbstractTableModel,
    QModelIndex,
    QSortFilterProxyModel,
)
from PySide6.QtGui import (
    QColor,
    QFont,
    QFontDatabase,
    QKeySequence,
    QShortcut,
    QTextCursor,
)
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QToolButton,
    QLineEdit,
    QComboBox,
    QTableView,
    QSplitter,
    QTreeWidget,
    QTreeWidgetItem,
    QPlainTextEdit,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QHeaderView,
    QAbstractItemView,
    QDialog,
    QMenu,
    QDialogButtonBox,
)
from . import capture, workers
from .session import Session, display_predicate
from .views import StreamDialog, endpoint

DISPLAY = Qt.ItemDataRole.DisplayRole
USER = Qt.ItemDataRole.UserRole
COLORS = {
    "TCP": "#355e8d",
    "TLS": "#7742a0",
    "HTTP": "#a34b2c",
    "mDNS": "#08775c",
    "DNS": "#007766",
    "ARP": "#86631c",
    "ICMP": "#9a4f30",
    "ICMPv6": "#9a4f30",
    "UDP": "#4d6d81",
}
STYLE = """
QMainWindow,QDialog,QWidget#body {background:#eef3f1;color:#22363c}
QLabel{color:#254044} QLabel#logo{color:#075e55;font-size:23px;font-weight:750}
QLabel#state{color:#105c53;background:#dbede5;border:1px solid #b7dacc;border-radius:9px;padding:4px 11px;font-weight:600}
QLabel#section{font-size:13px;font-weight:650;color:#274847} QLabel#count{color:#47645f}
QPushButton,QToolButton{background:#ffffff;color:#254643;border:1px solid #c2d1cb;border-radius:5px;padding:5px 11px;min-height:19px}
QPushButton:hover,QToolButton:hover{background:#e5f1eb} QPushButton:disabled{color:#95a4a1;background:#edf1ef}
QPushButton#primary{background:#087768;color:white;border-color:#087768;font-weight:650}
QPushButton#primary:disabled{background:#a4c0b8;color:#eef4ef}
QLineEdit,QComboBox{background:white;color:#22383b;border:1px solid #bdccc6;border-radius:5px;padding:5px;min-height:20px}
QTreeWidget,QTableView,QPlainTextEdit,QGraphicsView{background:white;color:#22383b;border:1px solid #c8d4cd;border-radius:4px;alternate-background-color:#f4f8f6;selection-background-color:#d2eae1;selection-color:#163b33}
QHeaderView::section{background:#e5ede8;color:#38544d;padding:5px;border:none;border-right:1px solid #cedbd2;font-weight:600}
QSplitter::handle{background:#e0e8e2} QToolTip{background:#fffde9;color:#2b4342}
"""


class Rows(QAbstractTableModel):
    columns = ("帧号", "时间 / s", "源地址", "目的地址", "协议", "字节", "摘要")

    def __init__(self):
        super().__init__()
        self.s = Session()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.s.records)

    def columnCount(self, parent=QModelIndex()):
        return len(self.columns)

    def headerData(self, section, orientation, role=DISPLAY):
        if role == DISPLAY and orientation == Qt.Orientation.Horizontal:
            return self.columns[section]
        return None

    def data(self, index, role=DISPLAY):
        if not index.isValid():
            return None
        r = self.s.records[index.row()]
        if role == Qt.ItemDataRole.ForegroundRole and index.column() == 4:
            return QColor(COLORS.get(self.s.highest(r), "#46645d"))
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 1, 5):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role == DISPLAY:
            p, f = r.packet, r.frame
            return (
                str(r.number),
                f"{f.timestamp-self.s.records[0].frame.timestamp:.6f}",
                p.src,
                p.dst,
                self.s.highest(r),
                str(f.wirelen),
                self.s.summary(r),
            )[index.column()]
        return None

    def replace(self, session):
        self.beginResetModel()
        self.s = session
        self.endResetModel()

    def append(self, frames):
        if not frames:
            return
        start = len(self.s.records)
        self.beginInsertRows(QModelIndex(), start, start + len(frames) - 1)
        for f in frames:
            self.s.append(f)
        self.endInsertRows()
        # New segments may complete a previously displayed HTTP line.
        if start:
            self.dataChanged.emit(self.index(0, 4), self.index(start - 1, 6), [DISPLAY])


class Filter(QSortFilterProxyModel):
    def __init__(self, model):
        super().__init__()
        self.setSourceModel(model)
        self.predicate = display_predicate("")
        self.setDynamicSortFilter(False)

    def refresh_rows(self, predicate=None):
        self.beginFilterChange()
        if predicate is not None:
            self.predicate = predicate
        self.endFilterChange(self.Direction.Rows)

    def filterAcceptsRow(self, row, parent):
        s = self.sourceModel().s
        return self.predicate(s, s.records[row])


def heading(text):
    label = QLabel(text)
    label.setObjectName("section")
    return label


def button(text, callback, primary=False):
    obj = QPushButton(text)
    if primary:
        obj.setObjectName("primary")
    obj.clicked.connect(callback)
    return obj


class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PacketScope · 网络嗅探器")
        self.resize(1240, 810)
        self.model = Rows()
        self.proxy = Filter(self.model)
        self.events = Queue()
        self.cancel = Event()
        self.mode = "idle"
        self.unsaved = False
        self.snapshots = deque(maxlen=6)
        self.process_error = ""
        self.hex_indices = []
        self.selected = None
        self.detail_signature = None
        self.body = QWidget()
        self.body.setObjectName("body")
        self.setCentralWidget(self.body)
        layout = QVBoxLayout(self.body)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.setSpacing(8)
        head = QHBoxLayout()
        logo = QLabel("PacketScope")
        logo.setObjectName("logo")
        head.addWidget(logo)
        head.addWidget(QLabel("网络嗅探器"))
        head.addStretch()
        self.state = QLabel("就绪")
        self.state.setObjectName("state")
        head.addWidget(self.state)
        layout.addLayout(head)
        actions = QHBoxLayout()
        self.devices = QComboBox()
        self.devices.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)
        self.devices.setToolTip("要监听的网络接口")
        try:
            priority = {"wi-fi": 0, "loopback": 1}
            for dev in sorted(
                capture.interfaces(),
                key=lambda d: priority.get(d.description.casefold(), 2),
            ):
                title = (
                    f"{dev.description}: {dev.name}"
                    if dev.description and dev.description != dev.name
                    else dev.name
                )
                self.devices.addItem(title, dev.name)
                if dev.description == "Loopback":
                    self.devices.setItemData(
                        self.devices.count() - 1,
                        "本机回环，用于观察 localhost 或 127.0.0.1 通信。",
                        Qt.ItemDataRole.ToolTipRole,
                    )
            found = self.devices.findData("lo0")
            if found >= 0:
                self.devices.setCurrentIndex(found)
        except (OSError, RuntimeError) as exc:
            self.devices.setToolTip(str(exc))
        self.bpf = QLineEdit()
        self.bpf.setPlaceholderText("捕获过滤器，例如 tcp port 80")
        self.start_btn = button("开始抓包", self.start_live, True)
        self.stop_btn = button("停止", self.stop)
        self.open_btn = button("打开文件", self.choose_file)
        self.save_btn = button("另存 PCAP", self.save)
        for w in (
            self.devices,
            self.bpf,
            self.start_btn,
            self.stop_btn,
            self.open_btn,
            self.save_btn,
        ):
            actions.addWidget(w, 1 if w is self.bpf else 0)
        layout.addLayout(actions)
        filters = QHBoxLayout()
        filters.addWidget(heading("显示过滤器"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText(
            "例如 tcp、mdns、tcp.port == 443 或 ip.addr == 127.0.0.1 and icmp"
        )
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.returnPressed.connect(self.apply_filter)
        self.filter_edit.textChanged.connect(
            lambda txt: self.apply_filter() if not txt else None
        )
        filters.addWidget(self.filter_edit, 1)
        filters.addWidget(button("应用", self.apply_filter))
        hints = QToolButton()
        hints.setText("常用规则 ▾")
        hints.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(hints)
        for text in (
            "tcp",
            "udp",
            "ip",
            "ipv6",
            "icmp or icmpv6",
            "http",
            "dns",
            "mdns",
            "tls",
            "tcp.port == 443",
            "frame.number == 1",
            "",
        ):
            menu.addAction(
                text or "清除过滤器", lambda checked=False, t=text: self.set_filter(t)
            )
        hints.setMenu(menu)
        filters.addWidget(hints)
        layout.addLayout(filters)
        self.filter_msg = QLabel()
        self.filter_msg.setStyleSheet("color:#963c25")
        self.filter_msg.hide()
        layout.addWidget(self.filter_msg)
        top = QWidget()
        top_l = QVBoxLayout(top)
        top_l.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        bar.addWidget(heading("数据包"))
        self.count = QLabel()
        self.count.setObjectName("count")
        bar.addWidget(self.count)
        bar.addStretch()
        self.proc_btn = button("按进程查看", self.process_list)
        self.stream_btn = button("追踪 TCP 流", self.trace)
        bar.addWidget(self.proc_btn)
        bar.addWidget(self.stream_btn)
        top_l.addLayout(bar)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(27)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        headview = self.table.horizontalHeader()
        headview.setStretchLastSection(True)
        for i, w in enumerate((52, 94, 167, 167, 75, 60)):
            self.table.setColumnWidth(i, w)
        self.table.selectionModel().currentRowChanged.connect(self.current_changed)
        self.table.doubleClicked.connect(
            lambda _: self.trace() if self.stream_btn.isEnabled() else None
        )
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.row_menu)
        top_l.addWidget(self.table)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["协议字段", "值"])
        self.tree.setColumnWidth(0, 220)
        self.tree.setAlternatingRowColors(True)
        self.tree.currentItemChanged.connect(self.highlight_field)
        self.tree.itemDoubleClicked.connect(self.follow_peer)
        self.hex = QPlainTextEdit()
        self.hex.setReadOnly(True)
        self.hex.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.hex.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        low = QSplitter(Qt.Orientation.Horizontal)
        for title, widget in [
            ("协议详情", self.tree),
            ("原始字节 · HEX / ASCII", self.hex),
        ]:
            area = QWidget()
            lay = QVBoxLayout(area)
            lay.setContentsMargins(0, 3, 0, 0)
            lay.addWidget(heading(title))
            lay.addWidget(widget)
            low.addWidget(area)
        low.setSizes([510, 630])
        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.addWidget(top)
        self.split.addWidget(low)
        self.split.setSizes([390, 320])
        layout.addWidget(self.split, 1)
        self.foot = QLabel("选择接口开始捕获，或打开 .pcap / .pcapng 文件。")
        self.foot.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.foot)
        self.pulse = QTimer(self)
        self.pulse.timeout.connect(self.poll)
        self.pulse.start(70)
        self.shortcuts = []
        for sequence, fun in [
            (QKeySequence.StandardKey.Open, self.choose_file),
            (QKeySequence.StandardKey.Save, self.save),
            ("Ctrl+L", self.filter_edit.setFocus),
        ]:
            sc = QShortcut(QKeySequence(sequence), self)
            sc.activated.connect(fun)
            self.shortcuts.append(sc)
        self.refresh_controls()

    def refresh_controls(self):
        idle = self.mode == "idle"
        self.start_btn.setEnabled(idle and self.devices.currentIndex() >= 0)
        self.stop_btn.setEnabled(self.mode in ("starting", "live"))
        self.open_btn.setEnabled(idle)
        self.save_btn.setEnabled(idle and bool(self.model.s.records))
        self.bpf.setEnabled(idle)
        self.devices.setEnabled(idle)
        self.proc_btn.setEnabled(bool(self.model.s.owners))
        self.stream_btn.setEnabled(
            self.selected is not None
            and self.model.s.analysis.meta[self.selected.number].stream is not None
        )
        self.count.setText(
            f"{self.proxy.rowCount():,} 显示　/　{len(self.model.s.records):,} 总数"
        )

    def discard_ok(self):
        if not self.unsaved:
            return True
        b = QMessageBox.StandardButton
        choice = QMessageBox.question(
            self,
            "当前捕获尚未保存",
            "是否保存当前捕获的数据包？",
            b.Save | b.Discard | b.Cancel,
            b.Save,
        )
        return self.save() if choice == b.Save else choice == b.Discard

    def clear_detail(self):
        self.selected = None
        self.detail_signature = None
        self.tree.clear()
        self.hex.clear()
        self.hex.setExtraSelections([])
        self.hex_indices = []
        self.stream_btn.setEnabled(False)

    def choose_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "打开抓包文件",
            str(Path(__file__).resolve().parents[1] / "examples"),
            "抓包文件 (*.pcap *.pcapng *.cap);;所有文件 (*)",
        )
        if path:
            self.load(path)

    def launch_task(self, fun, *args):
        Thread(target=fun, args=args, daemon=True).start()

    def load(self, path):
        if self.mode != "idle" or not self.discard_ok():
            return
        self.mode = "loading"
        self.state.setText("读取中")
        self.events = Queue()
        self.cancel = Event()
        self.refresh_controls()
        self.launch_task(workers.load_path, path, self.events, self.cancel)

    def install(self, s):
        self.clear_detail()
        self.model.replace(s)
        self.snaps_reset()
        self.filter_edit.clear()
        self.set_filter("")
        self.refresh_controls()
        if s.records:
            self.table.selectRow(0)

    def snaps_reset(self):
        self.snapshots.clear()
        self.process_error = ""

    def start_live(self):
        if self.mode != "idle" or not self.discard_ok():
            return
        self.events = Queue(maxsize=256)
        self.cancel = Event()
        self.mode = "starting"
        self.state.setText("打开接口…")
        self.refresh_controls()
        self.launch_task(
            workers.capture_live,
            self.devices.currentData(),
            self.bpf.text().strip(),
            self.events,
            self.cancel,
        )

    def stop(self):
        if self.mode in ("starting", "live"):
            self.cancel.set()
            self.mode = "stopping"
            self.state.setText("正在停止")
            self.refresh_controls()

    def save(self):
        if not self.model.s.records or self.mode != "idle":
            return False
        path, _ = QFileDialog.getSaveFileName(
            self, "保存所有已捕获帧", "capture.pcap", "PCAP (*.pcap)"
        )
        if not path:
            return False
        if Path(path).suffix.lower() not in (".pcap", ".cap"):
            path += ".pcap"
            if (
                Path(path).exists()
                and QMessageBox.question(self, "覆盖文件", f"覆盖 {path}？")
                != QMessageBox.StandardButton.Yes
            ):
                return False
        try:
            capture.save_file(path, (r.frame for r in self.model.s.records))
        except (OSError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "保存失败", str(exc))
            return False
        self.unsaved = False
        self.foot.setText("已保存全部数据包到 " + path)
        return True

    def apply_snapshot(self, stamp, owners):
        s = self.model.s
        if not owners:
            return
        # A tuple can be reused by another connection; only its newest observed
        # generation at the time of this snapshot can acquire this ownership.
        seen = set()
        for st in reversed(s.analysis.streams):
            if st.first > stamp:
                continue
            key = (st.left, st.right)
            if key in seen or key[::-1] in seen:
                continue
            seen.add(key)
            last = s.records[st.frames[-1] - 1].frame.timestamp
            if (st.finished_sending or st.reset) and last < stamp:
                continue
            for pair in (key, key[::-1]):
                name = owners.get(pair)
                if name:
                    s.owners.setdefault(st.id, {})[pair[0]] = name

    def poll(self):
        deadline = time.monotonic() + 0.045
        changed = False
        while time.monotonic() < deadline:
            try:
                kind, value = self.events.get_nowait()
            except Empty:
                break
            if kind == "loaded":
                self.mode = "idle"
                self.unsaved = False
                self.install(value)
                self.state.setText("离线分析")
                self.foot.setText(value.name)
            elif kind == "started":
                s = Session()
                s.name = value
                s.live = True
                self.unsaved = False
                self.install(s)
                self.mode = "stopping" if self.cancel.is_set() else "live"
                self.state.setText("捕获中 · " + value)
                self.foot.setText(
                    "接口 "
                    + value
                    + "　·　捕获规则："
                    + (self.bpf.text().strip() or "全部")
                )
                if not self.cancel.is_set():
                    self.launch_task(
                        workers.observe_processes, self.events, self.cancel
                    )
            elif kind == "batch":
                self.model.append(value)
                self.unsaved = True
                for stamp, owners in self.snapshots:
                    self.apply_snapshot(stamp, owners)
                changed = True
                if (
                    len(self.model.s.records) >= 100000
                    or self.model.s.stored_bytes >= 96 * 1024 * 1024
                ):
                    self.stop()
                    self.foot.setText("已达到单次捕获内存上限，请保存后继续。")
            elif kind == "owners":
                self.snapshots.append(value)
                self.apply_snapshot(*value)
                changed = True
            elif kind == "owner_error":
                self.process_error = value
                self.foot.setText("进程快照：" + value)
            elif kind == "end":
                self.mode = "idle"
                self.state.setText(
                    "捕获已停止"
                    if self.model.s.live
                    else ("离线分析" if self.model.s.records else "就绪")
                )
            elif kind == "error":
                self.mode = "idle"
                self.state.setText("操作失败")
                self.foot.setText(value)
                QMessageBox.warning(self, "操作失败", value)
            self.refresh_controls()
        if changed:
            if self.filter_edit.text().strip():
                self.proxy.refresh_rows()
            if self.selected is not None:
                meta = self.model.s.analysis.meta[self.selected.number]
                if self.detail_signature != (
                    meta.http_line,
                    meta.dns_peer,
                    meta.dns_ms,
                ):
                    self.refresh_selected_detail()
            self.refresh_controls()

    def refresh_selected_detail(self):
        item = self.tree.currentItem()
        span = item.data(0, USER) if item else None
        self.current_changed(self.table.currentIndex(), None)
        if span is not None:
            for i in range(self.tree.topLevelItemCount()):
                layer = self.tree.topLevelItem(i)
                for j in range(layer.childCount()):
                    field = layer.child(j)
                    if field.data(0, USER) == span:
                        self.tree.setCurrentItem(field)
                        return

    def apply_filter(self):
        text = self.filter_edit.text().strip()
        try:
            predicate = display_predicate(text)
        except (ValueError, RecursionError) as exc:
            self.filter_msg.setText("过滤条件无效，仍显示上次结果。" + str(exc))
            self.filter_msg.show()
            return
        self.filter_msg.hide()
        self.proxy.refresh_rows(predicate)
        if self.proxy.rowCount() == 0:
            self.clear_detail()
        elif not self.table.currentIndex().isValid():
            self.table.selectRow(0)
        self.refresh_controls()

    def set_filter(self, text):
        self.filter_edit.setText(text)
        self.apply_filter()

    def current_changed(self, current, previous):
        index = self.proxy.mapToSource(current)
        if not index.isValid():
            self.clear_detail()
            return
        r = self.model.s.records[index.row()]
        self.selected = r
        self.tree.clear()
        p = r.packet
        meta = self.model.s.analysis.meta[r.number]
        self.detail_signature = (meta.http_line, meta.dns_peer, meta.dns_ms)
        self.hex.setExtraSelections([])
        root = QTreeWidgetItem(
            self.tree,
            [f"Frame #{r.number}", f"{r.frame.wirelen} B · 捕获 {len(r.frame.data)} B"],
        )
        if meta.stream is not None:
            QTreeWidgetItem(root, ["TCP 流", str(meta.stream)])
        if meta.http_line:
            item = QTreeWidgetItem(root, ["TCP 重组 · HTTP 首行", meta.http_line])
            item.setToolTip(1, meta.http_line)
        if meta.dns_peer is not None:
            item = QTreeWidgetItem(
                root,
                ["DNS 配对帧（双击跳转）", f"#{meta.dns_peer} · {meta.dns_ms:.3f} ms"],
            )
            item.setData(0, USER + 1, meta.dns_peer)
        if p.problem:
            QTreeWidgetItem(root, ["解析提示", p.problem])
        root.setExpanded(True)
        for layer in p.layers:
            node = QTreeWidgetItem(self.tree, [layer.name, ""])
            for field in layer.fields:
                item = QTreeWidgetItem(node, [field.name, str(field.value)])
                item.setToolTip(1, str(field.value))
                item.setData(0, USER, (field.start, field.size))
            if layer is p.layers[-1]:
                node.setExpanded(True)
        data = r.frame.data
        # One line maps to 16 byte offsets in the packet; select cells by offset.
        lines = []
        self.hex_indices = []
        offset = 0
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            prefix = f"{i:06x}   "
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            display = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            line = f"{prefix}{hexpart:<47}   {display}"
            self.hex_indices.extend(
                offset + len(prefix) + 3 * j for j in range(len(chunk))
            )
            lines.append(line)
            offset += len(line) + 1
        self.hex.setPlainText("\n".join(lines))
        self.refresh_controls()

    def highlight_field(self, item, previous):
        if not item:
            return
        span = item.data(0, USER)
        if not span:
            return
        begin, size = span
        if size <= 0 or begin < 0 or begin >= len(self.hex_indices):
            return
        end = min(begin + size, len(self.hex_indices)) - 1
        selections = []
        first = begin
        while first <= end:
            last = min(end, (first // 16 + 1) * 16 - 1)
            sel = QTextEdit.ExtraSelection()
            cursor = QTextCursor(self.hex.document())
            cursor.setPosition(self.hex_indices[first])
            cursor.setPosition(
                self.hex_indices[last] + 2, QTextCursor.MoveMode.KeepAnchor
            )
            sel.cursor = cursor
            sel.format.setBackground(QColor("#f3cd76"))
            sel.format.setForeground(QColor("#302b1c"))
            selections.append(sel)
            first = last + 1
        self.hex.setExtraSelections(selections)
        cursor = QTextCursor(self.hex.document())
        cursor.setPosition(self.hex_indices[begin])
        self.hex.setTextCursor(cursor)
        self.hex.ensureCursorVisible()

    def select_number(self, number):
        if not 1 <= number <= len(self.model.s.records):
            return
        index = self.proxy.mapFromSource(self.model.index(number - 1, 0))
        if not index.isValid():
            self.set_filter("")
            index = self.proxy.mapFromSource(self.model.index(number - 1, 0))
        self.table.selectRow(index.row())
        self.table.scrollTo(index)

    def follow_peer(self, item, column):
        number = item.data(0, USER + 1)
        if number:
            self.select_number(number)

    def row_menu(self, point):
        idx = self.table.indexAt(point)
        if not idx.isValid():
            return
        self.table.selectRow(idx.row())
        if self.stream_btn.isEnabled():
            menu = QMenu(self)
            menu.addAction("追踪 TCP 流", self.trace)
            menu.exec(self.table.viewport().mapToGlobal(point))

    def trace(self):
        if self.selected is None:
            return
        sid = self.model.s.analysis.meta[self.selected.number].stream
        if sid is not None:
            StreamDialog(self.model.s, sid, self).exec()

    def process_list(self):
        s = self.model.s
        dialog = QDialog(self)
        dialog.resize(720, 420)
        dialog.setWindowTitle("按进程查看 TCP 流")
        layout = QVBoxLayout(dialog)
        layout.addWidget(heading("实时观测到的本机进程与连接"))
        tree = QTreeWidget()
        tree.setHeaderLabels(["进程 / TCP 流", "本地端点", "对端"])
        tree.setColumnWidth(0, 230)
        tree.setColumnWidth(1, 190)
        layout.addWidget(tree)
        groups = {}
        for sid, ownership in s.owners.items():
            stream = s.analysis.streams[sid]
            for ep, owner in ownership.items():
                if owner not in groups:
                    groups[owner] = QTreeWidgetItem(tree, [owner])
                other = stream.right if ep == stream.left else stream.left
                item = QTreeWidgetItem(
                    groups[owner], [f"流 #{sid}", endpoint(ep), endpoint(other)]
                )
                item.setData(0, USER, sid)
        tree.expandAll()

        def open_item(item, col):
            sid = item.data(0, USER)
            if sid is not None:
                StreamDialog(s, sid, dialog).exec()

        tree.itemDoubleClicked.connect(open_item)
        note = QLabel("双击连接可打开时序图。进程名称取自本机实时套接字快照。")
        layout.addWidget(note)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(dialog.close)
        layout.addWidget(close)
        dialog.exec()

    def closeEvent(self, event):
        if self.mode in ("starting", "live", "stopping"):
            self.stop()
            self.foot.setText("正在停止抓包，停止后可保存并关闭。")
            event.ignore()
            return
        if not self.discard_ok():
            event.ignore()
            return
        self.cancel.set()
        event.accept()
