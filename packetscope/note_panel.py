"""Shared, selectable teaching notes for the process and TCP views."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QScrollArea, QSizePolicy, QVBoxLayout, QWidget


def _label(name):
    label = QLabel()
    label.setObjectName(name)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    label.setWordWrap(True)
    label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
    return label


class _NoteSection(QWidget):
    def __init__(self, key):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        self.heading = _label(key + "Heading")
        self.title = _label(key + "Title")
        self.explanation = _label(key + "Explanation")
        self.evidence = _label(key + "Evidence")
        self.heading.setStyleSheet("color:#00796e;font-weight:600;")
        self.title.setStyleSheet("color:#203b36;font-size:15px;font-weight:600;")
        self.explanation.setStyleSheet("color:#233b37;")
        self.evidence.setStyleSheet("background:#edf4f0;color:#36564d;padding:7px;")
        for label in (self.heading, self.title, self.explanation, self.evidence):
            layout.addWidget(label)

    def display(self, heading, note):
        self.setVisible(note is not None)
        if note is None:
            return
        self.heading.setText(heading)
        self.title.setText(note.title)
        self.explanation.setText(note.explanation)
        self.evidence.setText(f"判断依据\n{note.evidence}" if note.evidence else "")
        self.evidence.setVisible(bool(note.evidence))


class NotePanel(QScrollArea):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("teachingPanel")
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setMinimumWidth(210)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(16)
        self.overview = _NoteSection("overview")
        self.detail = _NoteSection("detail")
        layout.addWidget(self.detail)
        layout.addWidget(self.overview)
        layout.addStretch()
        self.setWidget(content)
        self.set_notes(None)

    def set_notes(
        self,
        overview,
        detail=None,
        *,
        overview_label="连接概览",
        detail_label="所选报文",
    ):
        self.overview.display(overview_label, overview)
        self.detail.display(detail_label, detail)
        self.verticalScrollBar().setValue(0)
