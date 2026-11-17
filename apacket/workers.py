"""Worker functions only send data; Qt widgets are updated on the main thread."""

from __future__ import annotations
import queue
import time
from pathlib import Path
from . import capture, processes
from .session import Session


def load_path(path, events, cancel):
    try:
        session = Session()
        session.name = Path(path).name
        for frame in capture.read_file(path):
            if cancel.is_set():
                return
            session.append(frame)
        events.put(("loaded", session))
    except Exception as exc:
        events.put(("error", str(exc)))


def capture_live(device, bpf, events, stop):
    try:
        with capture.open_live(device, bpf) as handle:
            events.put(("started", device))
            batch = []
            last = time.monotonic()
            while not stop.is_set():
                frame = handle.read()
                if frame is not None:
                    batch.append(frame)
                if batch and (len(batch) >= 128 or time.monotonic() - last >= 0.08):
                    events.put(("batch", batch))
                    batch = []
                    last = time.monotonic()
                if frame is None:
                    stop.wait(0.008)
            if batch:
                events.put(("batch", batch))
    except Exception as exc:
        events.put(("error", str(exc)))
    finally:
        stop.set()
        events.put(("end", None))


def observe_processes(events, stop):
    while not stop.is_set():
        try:
            owners = processes.snapshot()
        except (OSError, RuntimeError) as exc:
            events.put(("owner_error", str(exc)))
            return
        if not stop.is_set():
            events.put(("owners", (time.time(), owners)))
        stop.wait(0.40)
