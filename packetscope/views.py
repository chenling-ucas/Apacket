from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush, QFont, QPen, QPolygonF
from PySide6.QtCore import QPointF
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QGraphicsScene,
    QGraphicsView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QTabWidget,
    QWidget,
)

INK = "#22343b"
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


class StreamDialog(QDialog):
    def __init__(self, session, sid, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"TCP 流 #{sid} · PacketScope")
        self.resize(820, 590)
        stream = session.analysis.streams[sid]
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 16)
        layout.addWidget(QLabel(f"<h2>TCP 流 #{sid}　双向时序</h2>"))
        owners = session.owners.get(sid, {})
        left, right = endpoint(stream.left), endpoint(stream.right)
        layout.addWidget(QLabel(f"{left}　⇄　{right}"))
        note = "　/　".join(f"{endpoint(k)}　{v}" for k, v in owners.items())
        layout.addWidget(
            QLabel(
                f'{len(stream.frames)} 帧　·　{note or ("未观测到本机进程" if session.live else "文件中没有实时进程快照")}'
            )
        )
        tabs = QTabWidget()
        layout.addWidget(tabs)
        scene = QGraphicsScene(self)
        view = QGraphicsView(scene)
        view.setBackgroundBrush(QColor("#f7faf9"))
        view.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        tabs.addTab(view, "时序图")
        table = QTableWidget(len(stream.frames), 5)
        table.setHorizontalHeaderLabels(
            ["帧号", "相对首帧 / ms", "方向", "事件", "载荷 / B"]
        )
        table.verticalHeader().hide()
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        tabs.addTab(table, "报文列表")

        def label(x, y, text, color=INK, size=10):
            item = scene.addSimpleText(text, QFont("Helvetica Neue", size))
            item.setBrush(QBrush(QColor(color)))
            item.setPos(x, y)

        cols = (172, 545)
        visible = min(len(stream.frames), 400)
        bottom = 58 + 34 * visible
        for x, title in zip(cols, ("A　" + left, "B　" + right)):
            label(x - 47, 8, title, TEAL)
            scene.addLine(
                x, 38, x, bottom, QPen(QColor("#a5c1ba"), 1, Qt.PenStyle.DashLine)
            )
        for i, no in enumerate(stream.frames):
            r = session.records[no - 1]
            p = r.packet
            m = session.analysis.meta[no]
            elapsed = (r.frame.timestamp - stream.first) * 1000
            forward = (p.src, p.sport) == stream.left
            summary = reason(p, m)
            items = [
                str(no),
                f"{elapsed:.3f}",
                "A → B" if forward else "B → A",
                summary,
                str(len(p.payload)),
            ]
            for col, value in enumerate(items):
                table.setItem(i, col, QTableWidgetItem(value))
            if i >= visible:
                continue
            y = 59 + i * 34
            x1, x2 = cols if forward else cols[::-1]
            color = QColor(TEAL if forward else ORANGE)
            sign = 1 if forward else -1
            label(7, y - 13, f"#{no}    {elapsed:.2f} ms", "#506d73", 9)
            label(230, y - 18, summary[:46], color.name(), 9)
            scene.addLine(x1, y, x2, y, QPen(color, 1.8))
            scene.addPolygon(
                QPolygonF(
                    [
                        QPointF(x2, y),
                        QPointF(x2 - sign * 8, y - 4),
                        QPointF(x2 - sign * 8, y + 4),
                    ]
                ),
                QPen(color),
                QBrush(color),
            )
        if len(stream.frames) > visible:
            label(12, bottom, "时序图显示前 400 帧，完整记录见报文列表。")
        scene.setSceneRect(0, 0, 735, bottom + 40)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)
