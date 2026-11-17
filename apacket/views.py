from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGraphicsScene,
    QGraphicsView,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
)

from .note_panel import NotePanel
from .teaching import StreamLesson

TEAL = "#00796e"
ORANGE = "#ae512d"


def endpoint(ep):
    host, port = ep
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def reason(packet, meta):
    if meta.http_line:
        return meta.http_line[:86]
    flags = packet.flags or 0
    names = [
        s
        for mask, s in ((2, "SYN"), (16, "ACK"), (1, "FIN"), (4, "RST"), (8, "PSH"))
        if flags & mask
    ]
    label = packet.protocol
    if label != "TCP":
        names.insert(0, label)
    return f'{" · ".join(names) or "TCP"}   {len(packet.payload)} B'


class FlowDiagram(QGraphicsView):
    row_chosen = Signal(int)
    top = 37
    row_height = 34
    limit = 400

    def __init__(self, rows, total, parent=None):
        super().__init__(parent)
        self.rows = rows
        self.total = total
        self.current_row = -1
        self.setObjectName("flowDiagram")
        self.setAccessibleName("TCP 双向时序图")
        self.setToolTip("点击箭头查看这一帧的作用，上下键切换。")
        self.viewport().setCursor(Qt.CursorShape.PointingHandCursor)
        self.setScene(QGraphicsScene(self))
        self.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        self.setBackgroundBrush(QColor("#f7faf9"))
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self._resize_scene()

    def _resize_scene(self):
        height = self.top + self.row_height * len(self.rows)
        if self.total > len(self.rows):
            height += 30
        self.scene().setSceneRect(0, 0, max(350, self.viewport().width()), height + 5)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_scene()

    def row_rect(self, row):
        return QRectF(
            0,
            self.top + row * self.row_height,
            self.sceneRect().width(),
            self.row_height,
        )

    def show_row(self, row):
        self.current_row = row
        if 0 <= row < len(self.rows):
            self.ensureVisible(self.row_rect(row), 0, 5)
        elif row >= len(self.rows):
            self.verticalScrollBar().setValue(self.verticalScrollBar().maximum())
        self.viewport().update()

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            point = self.mapToScene(event.position().toPoint())
            row = int((point.y() - self.top) // self.row_height)
            if 0 <= row < len(self.rows) and 0 <= point.x() < self.sceneRect().width():
                self.setFocus()
                self.row_chosen.emit(row)
                event.accept()
                return
        super().mousePressEvent(event)

    def keyPressEvent(self, event):
        if self.rows and event.key() in (Qt.Key.Key_Up, Qt.Key.Key_Down):
            step = 1 if event.key() == Qt.Key.Key_Down else -1
            row = max(0, min(self.current_row + step, len(self.rows) - 1))
            self.row_chosen.emit(row)
            event.accept()
            return
        super().keyPressEvent(event)

    def drawForeground(self, painter, exposed):
        # Draw only the visible rows. Every painted arrow has the same hit area as its text.
        painter.save()
        width = self.sceneRect().width()
        lane_a, lane_b = min(145, width * 0.32), width - 28
        bottom = self.top + len(self.rows) * self.row_height
        if 0 <= self.current_row < len(self.rows):
            rect = self.row_rect(self.current_row)
            painter.fillRect(rect, QColor("#dceee7"))
            painter.fillRect(QRectF(0, rect.top(), 3, rect.height()), QColor(TEAL))
        painter.setPen(QPen(QColor("#a5c1ba"), 1, Qt.PenStyle.DashLine))
        for x in (lane_a, lane_b):
            painter.drawLine(QPointF(x, self.top - 6), QPointF(x, bottom))
        center = Qt.AlignmentFlag.AlignCenter
        painter.setFont(QFont("Helvetica Neue", 10))
        painter.setPen(QColor("#32594f"))
        if exposed.top() < self.top:
            painter.drawText(
                QRectF(8, 2, lane_a - 30, self.top - 5),
                Qt.AlignmentFlag.AlignVCenter,
                "帧号 / 时间",
            )
            for x, title in ((lane_a, "A"), (lane_b, "B")):
                painter.drawText(QRectF(x - 12, 2, 24, self.top - 6), center, title)
        painter.setFont(QFont("Helvetica Neue", 9))
        metrics = painter.fontMetrics()
        start = max(0, int((exposed.top() - self.top) // self.row_height))
        stop = min(
            len(self.rows), int((exposed.bottom() - self.top) // self.row_height) + 1
        )
        for i in range(start, stop):
            no, elapsed, forward, summary = self.rows[i]
            top = self.top + i * self.row_height
            y = top + self.row_height - 7
            painter.setPen(QColor("#44635c"))
            stamp = f"#{no}   {elapsed:.2f} ms"
            time_box = QRectF(8, top, lane_a - 18, self.row_height)
            painter.drawText(
                time_box,
                Qt.AlignmentFlag.AlignVCenter,
                metrics.elidedText(
                    stamp, Qt.TextElideMode.ElideRight, int(time_box.width())
                ),
            )
            x1, x2 = (lane_a, lane_b) if forward else (lane_b, lane_a)
            color = QColor(TEAL if forward else ORANGE)
            painter.setPen(QPen(color, 1.7))
            event_box = QRectF(
                lane_a + 8, top + 1, lane_b - lane_a - 16, self.row_height - 11
            )
            caption = metrics.elidedText(
                summary, Qt.TextElideMode.ElideRight, int(event_box.width())
            )
            painter.drawText(event_box, center, caption)
            painter.drawLine(QPointF(x1, y), QPointF(x2, y))
            tip_base = x2 - 7 if forward else x2 + 7
            painter.setBrush(color)
            painter.drawPolygon(
                QPolygonF(
                    [QPointF(x2, y), QPointF(tip_base, y - 3), QPointF(tip_base, y + 3)]
                )
            )
        if self.total > len(self.rows) and exposed.bottom() >= bottom:
            painter.setPen(QColor("#44635c"))
            painter.drawText(
                QRectF(8, bottom, width - 16, 28),
                Qt.AlignmentFlag.AlignVCenter,
                f"时序图显示前 {self.limit} 帧，完整记录见报文列表。",
            )
        painter.restore()


class StreamDialog(QDialog):
    def __init__(self, session, sid, parent=None, *, initial_frame=None):
        super().__init__(parent)
        self.setWindowTitle(f"TCP 流 #{sid} · Apacket")
        self.resize(1060, 620)
        stream = session.analysis.streams[sid]
        self.frames = list(stream.frames)
        self.lesson = StreamLesson(session, sid)
        self.overview = self.lesson.overview()
        self.selected_frame = None
        self.tabs = QTabWidget()
        self.tabs.setObjectName("streamTabs")
        self.table = QTableWidget(len(self.frames), 5)
        self.table.setObjectName("streamPackets")
        self.panel = NotePanel()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 12)
        layout.addWidget(QLabel(f"<h2>TCP 流 #{sid}　双向时序</h2>"))
        owners = session.owners.get(sid, {})
        left, right = endpoint(stream.left), endpoint(stream.right)
        endpoints = QLabel(f"A　{left}　　 ⇄ 　　B　{right}")
        endpoints.setWordWrap(True)
        layout.addWidget(endpoints)
        owner_text = "　/　".join(f"{endpoint(k)}　{v}" for k, v in owners.items())
        if not owner_text:
            owner_text = (
                "未观测到本机进程" if session.live else "文件中没有实时进程快照"
            )
        info = QLabel()
        info.setTextFormat(Qt.TextFormat.PlainText)
        info.setWordWrap(True)
        count = (
            f"打开时共 {len(self.frames)} 帧"
            if session.live
            else f"{len(self.frames)} 帧"
        )
        info.setText(f"{count}　·　{owner_text}")
        layout.addWidget(info)

        self.table.setHorizontalHeaderLabels(
            ["帧号", "相对首帧 / ms", "方向", "事件", "载荷 / B"]
        )
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for col, width in ((0, 60), (1, 114), (2, 70), (4, 76)):
            self.table.setColumnWidth(col, width)

        diagram_rows = []
        for row, no in enumerate(self.frames):
            record = session.records[no - 1]
            packet = record.packet
            elapsed = (record.frame.timestamp - stream.first) * 1000
            forward = (packet.src, packet.sport) == stream.left
            summary = reason(packet, session.analysis.meta[no])
            values = (
                str(no),
                f"{elapsed:.3f}",
                "A → B" if forward else "B → A",
                summary,
                str(len(packet.payload)),
            )
            for col, value in enumerate(values):
                self.table.setItem(row, col, QTableWidgetItem(value))
            if row < FlowDiagram.limit:
                diagram_rows.append((no, elapsed, forward, summary))
        self.graph = FlowDiagram(diagram_rows, len(self.frames))
        self.tabs.addTab(self.graph, "时序图")
        self.tabs.addTab(self.table, "报文列表")
        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)
        split.addWidget(self.tabs)
        split.addWidget(self.panel)
        split.setSizes([630, 350])
        layout.addWidget(split, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)

        self.graph.row_chosen.connect(lambda row: self.table.setCurrentCell(row, 0))
        self.table.currentCellChanged.connect(self._choose_packet)
        self.tabs.currentChanged.connect(self._reveal_selection)
        self.panel.set_notes(self.overview)
        if self.frames:
            row = (
                self.frames.index(initial_frame) if initial_frame in self.frames else 0
            )
            if row >= self.graph.limit:
                self.tabs.setCurrentWidget(self.table)
            self.table.setCurrentCell(row, 0)

    def showEvent(self, event):
        super().showEvent(event)
        self._reveal_selection(self.tabs.currentIndex())

    def _choose_packet(self, row, column, old_row, old_column):
        if row < 0 or row == old_row:
            return
        self.selected_frame = self.frames[row]
        self.panel.set_notes(
            self.overview,
            self.lesson.frame(self.selected_frame),
            detail_label=f"所选报文　#{self.selected_frame}",
        )
        self.graph.show_row(row)

    def _reveal_selection(self, index):
        row = self.table.currentRow()
        if row < 0:
            return
        if self.tabs.currentWidget() is self.table:
            self.table.scrollToItem(self.table.item(row, 0))
        else:
            self.graph.show_row(row)
