"""Run PacketScope with an optional capture-file path."""

import sys
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication
from .gui import Window, STYLE


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("PacketScope")
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)
    window = Window()
    window.show()
    if len(sys.argv) > 1:
        QTimer.singleShot(0, lambda: window.load(sys.argv[1]))
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
