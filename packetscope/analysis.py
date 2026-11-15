"""Associate decoded frames using the addresses, ports and sequence numbers on the wire."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .decode import detect_http_line

Endpoint = tuple[str, int]
Connection = tuple[Endpoint, Endpoint]

_MAX_LINE = 8192
_MAX_PIECES = 96
_MAX_PENDING_DNS = 4096


def signed_distance(sequence: int, origin: int) -> int:
    """Signed TCP serial-number difference, including wrap around 2**32."""
    return ((sequence - origin + 0x80000000) & 0xffffffff) - 0x80000000


class _FirstLine:
    """Watch a bounded prefix per direction. Overlaps keep the bytes seen first."""
    def __init__(self, start: int | None = None):
        self.origin = start
        self.anchored = start is not None
        self.pieces: list[tuple[int, bytes, int]] = []
        self.stored = 0
        self.done = False

    def feed(self, seq: int, data: bytes, number: int) -> tuple[str, set[int]] | None:
        if self.done or not data:
            return None
        if self.origin is None:
            self.origin = seq
        offset = signed_distance(seq, self.origin)
        minimum = 0 if self.anchored else -_MAX_LINE
        left, right = max(minimum, offset), min(_MAX_LINE, offset + len(data))
        if right <= left:
            return None
        chunk = data[left - offset:right - offset]
        if any(pos == left and old == chunk for pos, old, _ in self.pieces):
            return None
        if len(self.pieces) >= _MAX_PIECES or self.stored + len(chunk) > 3 * _MAX_LINE:
            self.finish()
            return None
        self.pieces.append((left, chunk, number))
        self.stored += len(chunk)
        start = 0 if self.anchored else min(pos for pos, _, _ in self.pieces)
        end = min(start + _MAX_LINE, max(pos + len(raw) for pos, raw, _ in self.pieces))
        buf = bytearray(end - start)
        present = bytearray(end - start)
        # Reverse insertion order makes the first copy win on retransmission/overlap.
        for pos, raw, _ in reversed(self.pieces):
            lo, hi = max(pos, start), min(pos + len(raw), end)
            if hi > lo:
                buf[lo - start:hi - start] = raw[lo - pos:hi - pos]
                present[lo - start:hi - start] = b'\x01' * (hi - lo)
        gap = present.find(0)
        contiguous = bytes(buf if gap < 0 else buf[:gap])
        if self.anchored and contiguous and not 65 <= contiguous[0] <= 90:
            self.finish()
            return None
        line_end = contiguous.find(b'\r\n')
        if line_end < 0:
            if len(contiguous) >= _MAX_LINE:
                self.finish()
            return None
        line = detect_http_line(contiguous)
        if line:
            frames = {n for pos, raw, n in self.pieces
                      if pos < start + line_end + 2 and pos + len(raw) > start}
            self.finish()
            return line, frames
        if self.anchored:
            self.finish()
        return None

    def finish(self):
        self.done = True
        self.pieces.clear()
        self.stored = 0


@dataclass
class Meta:
    stream: int | None = None
    direction: str = ''
    http_line: str = ''
    dns_peer: int | None = None
    dns_ms: float | None = None


@dataclass
class Stream:
    id: int
    left: Endpoint
    right: Endpoint
    first: float
    frames: list[int] = field(default_factory=list)
    http_events: list[tuple[int, str]] = field(default_factory=list)
    initial_seq: dict[Endpoint, int] = field(default_factory=dict, repr=False)
    scanners: dict[Endpoint, _FirstLine] = field(default_factory=dict, repr=False)
    finished_sending: set[Endpoint] = field(default_factory=set, repr=False)
    reset: bool = field(default=False, repr=False)


class Analyzer:
    """Frame numbers are 1-based; stream IDs follow order of first observation."""
    def __init__(self):
        self.meta: dict[int, Meta] = {}
        self.streams: list[Stream] = []
        self._current: dict[Connection, Stream] = {}
        self._dns: OrderedDict[tuple, tuple[int, float]] = OrderedDict()

    def add(self, number: int, timestamp: float, packet) -> Meta:
        meta = self.meta[number] = Meta()
        if packet.sport is None or packet.dport is None:
            return meta
        layers = {layer.upper() for layer in packet.protocols}
        source, target = (packet.src, packet.sport), (packet.dst, packet.dport)
        if 'TCP' in layers:
            self._tcp(number, timestamp, packet, source, target, meta)
        if 'DNS' in layers and 'MDNS' not in layers and packet.dns_response is not None:
            self._pair_dns(number, timestamp, packet, source, target, meta)
        return meta

    def _tcp(self, number, timestamp, packet, source, target, meta):
        key = (source, target) if source <= target else (target, source)
        stream = self._current.get(key)
        syn = bool(packet.flags & 0x02)
        ack = bool(packet.flags & 0x10)
        # A repeated SYN with the same ISN belongs to the same handshake.
        if syn and not ack and stream:
            if (stream.reset or stream.finished_sending
                    or stream.initial_seq.get(source) != packet.seq):
                stream = None
        if stream is None:
            left, right = (target, source) if syn and ack else (source, target)
            stream = Stream(len(self.streams), left, right, timestamp)
            self.streams.append(stream)
            self._current[key] = stream
        stream.frames.append(number)
        meta.stream = stream.id
        meta.direction = '→' if source == stream.left else '←'
        if syn:
            stream.initial_seq[source] = packet.seq
            if ack:
                stream.initial_seq.setdefault(target, (packet.ack - 1) & 0xffffffff)
        if packet.payload:
            scanner = stream.scanners.get(source)
            if scanner is None:
                isn = stream.initial_seq.get(source)
                scanner = stream.scanners[source] = _FirstLine(
                    None if isn is None else (isn + 1) & 0xffffffff)
            found = scanner.feed((packet.seq + int(syn)) & 0xffffffff, packet.payload, number)
            if found:
                line, frames = found
                for frame in frames:
                    self.meta[frame].http_line = line
                stream.http_events.append((number, line))
        if packet.flags & 0x01:
            stream.finished_sending.add(source)
        if packet.flags & 0x04:
            stream.reset = True
        if stream.reset or len(stream.finished_sending) == 2:
            for scanner in stream.scanners.values():
                scanner.finish()

    def _pair_dns(self, number, timestamp, packet, source, target, meta):
        if packet.dns_id is None or not packet.dns_question:
            return
        while self._dns and timestamp - next(iter(self._dns.values()))[1] > 60:
            self._dns.popitem(last=False)
        endpoints = (target, source) if packet.dns_response else (source, target)
        key = (endpoints, 'TCP' if 'TCP' in packet.protocols else 'UDP', packet.dns_id,
               packet.dns_question.rstrip('.').casefold(), packet.dns_qtype)
        if packet.dns_response:
            item = self._dns.pop(key, None)
            if item:
                request, sent = item
                self.meta[request].dns_peer = number
                meta.dns_peer = request
                self.meta[request].dns_ms = meta.dns_ms = (timestamp - sent) * 1000
        else:
            self._dns[key] = (number, timestamp)
            self._dns.move_to_end(key)
            if len(self._dns) > _MAX_PENDING_DNS:
                self._dns.popitem(last=False)
