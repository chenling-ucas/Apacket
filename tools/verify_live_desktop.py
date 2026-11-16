"""Exercise PacketScope's desktop capture and process views with two local TCP peers.

Use the Python selected by the release launcher. The harness can live outside the
ZIP: pass --project to select the extracted, unmodified application directory.
"""
from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime
import json
import os
import platform
import queue
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HOST = "127.0.0.1"


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def peer(role, port, marker, stop):
    """A child reports its own PID (also works with Windows' venv redirector)."""
    deadline = time.monotonic() + 180
    if role == "server":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((HOST, 0))
            listener.listen()
            print(json.dumps([os.getpid(), listener.getsockname()[1]]), flush=True)
            listener.settimeout(0.25)
            while not stop.exists() and time.monotonic() < deadline:
                try:
                    conn, _ = listener.accept()
                    break
                except TimeoutError:
                    pass
            else:
                return
            with conn:
                conn.settimeout(0.4)
                while not stop.exists() and time.monotonic() < deadline:
                    try:
                        data = conn.recv(2048)
                    except TimeoutError:
                        continue
                    if not data:
                        break
                    conn.sendall(data)
    else:
        with socket.create_connection((HOST, port), timeout=5) as conn:
            print(json.dumps([os.getpid(), conn.getsockname()[1]]), flush=True)
            while not stop.exists() and time.monotonic() < deadline:
                conn.sendall(marker)
                remaining = len(marker)
                chunks = []
                while remaining:
                    part = conn.recv(remaining)
                    if not part:
                        raise RuntimeError("echo server closed")
                    chunks.append(part)
                    remaining -= len(part)
                check(b"".join(chunks) == marker, "echo data mismatch")
                time.sleep(0.12)


@contextlib.contextmanager
def start_peer(role, port, marker, stop):
    args = [sys.executable, str(Path(__file__).resolve()), "--peer", role,
            str(port), marker.decode(), str(stop)]
    with subprocess.Popen(args, stdout=subprocess.PIPE, text=True) as child:
        try:
            lines = queue.Queue()
            threading.Thread(target=lambda: lines.put(child.stdout.readline()), daemon=True).start()
            try:
                line = lines.get(timeout=15)
            except queue.Empty:
                raise RuntimeError(f"{role} did not report its listening or connected socket") from None
            check(line, f"{role} stopped before opening its socket")
            pid, bound_port = json.loads(line)
            yield pid, bound_port
        finally:
            stop.touch()
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            child.stdout.close()


def permissions():
    if sys.platform == "win32":
        return {"administrator": bool(ctypes.windll.shell32.IsUserAnAdmin())}
    import grp
    result = {"euid": os.geteuid(), "groups": [
        grp.getgrgid(gid).gr_name for gid in sorted(set(os.getgroups()) | {os.getegid()})]}
    if sys.platform.startswith("linux"):
        lines = Path("/proc/self/status").read_text().splitlines()
        result["cap_eff"] = next(line.split()[1] for line in lines if line.startswith("CapEff:"))
    return result


def linux_dumpcap_children():
    """Read the OS process tree while the GUI is actively capturing."""
    found = set()
    for task in Path("/proc/self/task").glob("*/children"):
        try:
            for child in task.read_text().split():
                if Path(f"/proc/{child}/comm").read_text().strip() == "dumpcap":
                    found.add(int(child))
        except (FileNotFoundError, PermissionError):
            continue
    return sorted(found)


def desktop(args, result):
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtTest import QTest
    from PySide6.QtWidgets import QApplication, QLabel, QMessageBox
    from packetscope import capture, gui
    from packetscope.process_view import ProcessDialog
    from packetscope.views import StreamDialog, endpoint

    check(Path(gui.__file__).resolve() == (args.project / "packetscope/gui.py").resolve(),
          "Imported application does not match --project")
    app = QApplication([sys.argv[0]])
    app.setApplicationName("PacketScope")
    app.setStyle("Fusion")
    app.setStyleSheet(gui.STYLE)
    result["qt_platform"] = app.platformName()
    w = gui.Window()
    w.show()
    app.processEvents()
    errors = []

    def dismiss_error():
        box = app.activeModalWidget()
        if isinstance(box, QMessageBox):
            errors.append(box.text())
            box.reject()

    watcher = QTimer()
    watcher.timeout.connect(dismiss_error)
    watcher.start(80)

    def wait_for(description, predicate):
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            app.processEvents()
            if errors or w.process_error:
                raise RuntimeError(" / ".join(errors + [w.process_error]).strip(" /"))
            value = predicate()
            if value:
                return value
            time.sleep(0.025)
        raise RuntimeError(f"Timeout waiting for {description}; {w.state.text()}; "
                           f"{w.foot.text()}; frames={w.model.rowCount()}; owners={w.model.s.owners}")

    def inspect_modal(open_dialog, dialog_type, inspect):
        # Production dialogs call exec(). This timer runs inside that nested Qt event loop.
        seen, problem = [], []
        deadline = time.monotonic() + args.timeout
        timer = QTimer()

        def visit():
            modal = app.activeModalWidget()
            if isinstance(modal, dialog_type):
                timer.stop()
                try:
                    seen.append(True)
                    inspect(modal)
                except Exception as exc:
                    problem.append(exc)
                finally:
                    modal.accept()
            elif time.monotonic() >= deadline:
                timer.stop()
                if modal:
                    modal.reject()

        timer.timeout.connect(visit)
        timer.start(80)
        try:
            open_dialog()
        finally:
            timer.stop()
        if problem:
            raise problem[0]
        check(seen, f"{dialog_type.__name__} did not open")

    def screenshot(widget, filename):
        if args.artifacts:
            check(widget.grab().save(str(args.artifacts / filename)), f"Cannot save {filename}")

    devices = [w.devices.itemData(i) for i in range(w.devices.count())]
    if args.interface:
        device = args.interface
    elif sys.platform == "win32":
        device = next((d for d in devices if d.lower().endswith("npf_loopback")), None)
    else:
        device = "lo0" if sys.platform == "darwin" else "lo"
    check(device in devices, f"Loopback device absent: {devices}; {w.devices.toolTip()}")
    w.devices.setCurrentIndex(devices.index(device))
    result["device"] = device
    marker = ("PacketScope-check-" + secrets.token_hex(12)).encode("ascii")

    try:
        with tempfile.TemporaryDirectory(prefix="packetscope-live-") as temp:
            stop = Path(temp) / "stop"
            with start_peer("server", 0, marker, stop) as (server_pid, server_port):
                rule = f"tcp and host {HOST} and port {server_port}"
                result.update(server_pid=server_pid, server_port=server_port, capture_filter=rule)
                w.bpf.setText(rule)
                check(w.start_btn.isEnabled(), "Start capture is disabled")
                w.start_btn.click()
                wait_for("capture start", lambda: w.mode == "live")
                with start_peer("client", server_port, marker, stop) as (client_pid, client_port):
                    result.update(client_pid=client_pid, client_port=client_port)
                    expected = {(HOST, server_port): server_pid, (HOST, client_port): client_pid}
                    check(len(expected) == 2 and server_pid != client_pid, "Peers are not distinct")
                    session = w.model.s

                    def matching_stream():
                        for stream in session.analysis.streams:
                            if {stream.left, stream.right} != set(expected):
                                continue
                            labels = session.owners.get(stream.id, {})
                            if not all(labels.get(ep, "").endswith(f"(PID {pid})")
                                       or labels.get(ep) == f"PID {pid}" for ep, pid in expected.items()):
                                continue
                            packets = [session.records[n - 1].packet for n in stream.frames]
                            if {p.sport for p in packets if marker in p.payload} == {server_port, client_port}:
                                return stream

                    stream = wait_for("captured echo request/reply and both correct PIDs", matching_stream)
                    if sys.platform.startswith("linux"):
                        result["active_dumpcap_pids"] = linux_dumpcap_children()
                    if capture._library.cache_info().currsize:
                        result["capture_library"] = str(capture._library()._name)
                    w.stop_btn.click()
                    wait_for("capture stop", lambda: w.mode == "idle")
        frames = list(stream.frames)
        owners = session.owners[stream.id]
        check(len(session.records) == len(frames), "An unrelated frame passed the capture filter")
        result.update(stream_id=stream.id, captured_frames=len(frames),
                      marker=marker.decode(), marker_verified_both_directions=True,
                      owners={endpoint(ep): owners[ep] for ep in expected})
        check(w.proc_btn.isEnabled(), "Process view disabled after live capture")
        frame_ids = lambda table: [int(table.model().index(i, 0).data())
                                   for i in range(table.model().rowCount())]
        filter_counts = {}
        for ep, pid in expected.items():
            label = owners[ep]
            w.filter_edit.setText(f'process == "{label}"')
            QTest.keyClick(w.filter_edit, Qt.Key.Key_Return)
            check(frame_ids(w.table) == frames, f"Display filter for PID {pid} failed")
            filter_counts[str(pid)] = w.proxy.rowCount()
        result["display_filter_rows"] = filter_counts
        screenshot(w, "main.png")

        def inspect_stream(dialog):
            check(f"#{stream.id} " in dialog.windowTitle(), "Opened a different TCP flow")
            check(frame_ids(dialog.table) == frames, "Trace frame IDs differ")
            labels = "\n".join(item.text() for item in dialog.findChildren(QLabel))
            check(all(label in labels for label in owners.values()), "Trace omits owner labels")
            result["trace_frame_ids"] = frames
            screenshot(dialog, "tcp-stream.png")

        def inspect_tree(dialog):
            tree = dialog.tree
            rows = {}
            for i in range(tree.topLevelItemCount()):
                group = tree.topLevelItem(i)
                for j in range(group.childCount()):
                    item = group.child(j)
                    rows[(group.text(0), item.text(1), item.text(2), item.text(0))] = item
            for ep in expected:
                peer_ep = next(other for other in expected if other != ep)
                key = (owners[ep], endpoint(ep), endpoint(peer_ep), f"流 #{stream.id}")
                check(key in rows, f"Missing process-tree entry: {key}")
            result["process_tree_rows"] = [list(row) for row in rows]
            item = rows[key]
            tree.setCurrentItem(item)
            tree.scrollToItem(item)
            app.processEvents()
            screenshot(dialog, "process-tree.png")
            pos = tree.visualItemRect(item).center()
            QTest.mouseClick(tree.viewport(), Qt.MouseButton.LeftButton, pos=pos)
            inspect_modal(lambda: QTest.mouseDClick(tree.viewport(), Qt.MouseButton.LeftButton, pos=pos),
                          StreamDialog, inspect_stream)

        inspect_modal(w.proc_btn.click, ProcessDialog, inspect_tree)
        if args.artifacts:
            dest = args.artifacts / "loopback.pcap"
            capture.save_file(dest, (r.frame for r in session.records))
            check(len(list(capture.read_file(dest))) == len(frames), "Saved PCAP frame count differs")
    finally:
        if w.mode in ("live", "starting"):
            w.stop_btn.click()
        deadline = time.monotonic() + 3
        while w.mode != "idle" and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.02)
        watcher.stop()
        w.hide()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--artifacts", type=Path, help="write evidence JSON, PCAP and three window PNGs here")
    parser.add_argument("--interface", help="default: operating system loopback interface")
    parser.add_argument("--expect-platform", choices=("linux", "macos", "windows"))
    parser.add_argument("--timeout", type=float, default=35, help="maximum seconds per UI step")
    args = parser.parse_args()
    args.project = args.project.resolve()
    if args.artifacts:
        args.artifacts.mkdir(parents=True, exist_ok=True)
    result = {"ok": False, "platform": platform.platform(), "machine": platform.machine(),
              "python_executable": sys.executable, "python_version": platform.python_version(),
              "project": str(args.project), "started": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        result["permissions"] = permissions()
        actual = {"win32": "windows", "darwin": "macos", "linux": "linux"}.get(sys.platform)
        check(not args.expect_platform or actual == args.expect_platform,
              f"Expected {args.expect_platform}, got {actual}")
        sys.path.insert(0, str(args.project))
        desktop(args, result)
        result["ok"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    result["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    data = json.dumps(result, ensure_ascii=False, indent=2)
    if args.artifacts:
        (args.artifacts / "acceptance.json").write_text(data + "\n", encoding="utf-8")
    # The Windows console or a redirected PowerShell pipe may have a legacy code page.
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--peer":
        peer(sys.argv[2], int(sys.argv[3]), sys.argv[4].encode("ascii"), Path(sys.argv[5]))
    else:
        sys.exit(main())
