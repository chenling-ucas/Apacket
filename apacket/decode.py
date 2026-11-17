"""Decode captured bytes into display fields. Offsets are absolute within the frame."""
from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass, field


@dataclass(slots=True)
class Field:
    name: str
    value: str
    start: int
    size: int


@dataclass(slots=True)
class Layer:
    name: str
    fields: list[Field] = field(default_factory=list)

    def add(self, name, value, start, size):
        self.fields.append(Field(name, str(value), start, size))


@dataclass(slots=True)
class Packet:
    src: str = ""
    dst: str = ""
    sport: int | None = None
    dport: int | None = None
    protocol: str = "Data"
    protocols: list[str] = field(default_factory=list)
    info: str = ""
    layers: list[Layer] = field(default_factory=list)
    flags: int = 0
    seq: int | None = None
    ack: int | None = None
    payload: bytes = b""
    dns_id: int | None = None
    dns_response: bool | None = None
    dns_question: str = ""
    dns_qtype: int | None = None
    http_line: str = ""
    problem: str = ""
    # Full application payload as declared by IP, useful for truncated TCP segments.
    tcp_payload_len: int | None = None

    def layer(self, name: str) -> Layer:
        self.protocol = name
        self.protocols.append(name)
        layer = Layer(name)
        self.layers.append(layer)
        return layer


class DecodeIssue(ValueError):
    """A wire length, address or required structure is incomplete or malformed."""


def need(data, start, size, layer):
    if start < 0 or size < 0 or start + size > len(data):
        raise DecodeIssue(f"{layer} 字段超出捕获范围")


def u16(data, pos):
    return struct.unpack_from("!H", data, pos)[0]


def u32(data, pos):
    return struct.unpack_from("!I", data, pos)[0]


def addr(raw):
    return str(ipaddress.ip_address(bytes(raw)))


def mac(raw):
    return bytes(raw).hex(":")


_TYPES = {0x0800: "IPv4", 0x86DD: "IPv6", 0x0806: "ARP", 0x8100: "802.1Q", 0x88A8: "802.1ad"}
_IP_PROTO = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
_DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 41: "OPT", 47: "NSEC", 64: "SVCB", 65: "HTTPS", 255: "ANY"}
_TCP_FLAGS = [(1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (0x10, "ACK"), (0x20, "URG"),
              (0x40, "ECE"), (0x80, "CWR"), (0x100, "NS")]

# HTTP/1.x request/status line. Require a complete line so a TCP segment's end
# cannot be mistaken for a message boundary.
_HTTP_LINE = re.compile(
    rb"(?:[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31} [^\x00-\x20\x7f]+ HTTP/1\.[01]"
    rb"|HTTP/1\.[01] [1-5][0-9][0-9](?: [^\r\n]*)?)\r\n"
)


def detect_http_line(payload: bytes) -> str:
    match = _HTTP_LINE.match(payload, 0, 16384)
    return match[0][:-2].decode("latin-1", "replace") if match else ""


def type_label(code):
    return f"{_TYPES.get(code, 'Unknown')} (0x{code:04x})"


def decode(data: bytes, linktype: int) -> Packet:
    """Decode one link-layer frame without reading outside a captured or inner packet."""
    p = Packet()
    try:
        _link(p, data, linktype)
    except DecodeIssue as exc:
        p.problem = str(exc)
        if p.info:
            p.info += "  ·  "
        p.info += p.problem
    if not p.info:
        p.info = f"{p.protocol} · {len(data)} B"
    return p


def _link(p, data, linktype):
    if linktype == 1:
        layer = p.layer("Ethernet")
        need(data, 0, 14, "Ethernet")
        p.dst, p.src = mac(data[0:6]), mac(data[6:12])
        layer.add("Destination MAC", p.dst, 0, 6)
        layer.add("Source MAC", p.src, 6, 6)
        etype, pos = u16(data, 12), 14
        layer.add("EtherType", type_label(etype), 12, 2)
        while etype in (0x8100, 0x88A8, 0x9100):
            need(data, pos, 4, "VLAN")
            tag = p.layer("VLAN")
            tag.add("VLAN ID", u16(data, pos) & 0xfff, pos, 2)
            etype = u16(data, pos + 2)
            tag.add("EtherType", type_label(etype), pos + 2, 2)
            pos += 4
    elif linktype in (0, 108):  # NULL is native-endian on the recording host.
        layer = p.layer("Loopback")
        need(data, 0, 4, "Loopback")
        big = int.from_bytes(data[:4], "big")
        little = int.from_bytes(data[:4], "little")
        families = {2: 0x0800, 10: 0x86DD, 24: 0x86DD, 28: 0x86DD, 30: 0x86DD}
        family = big if linktype == 108 or big in families else little
        etype, pos = families.get(family), 4
        layer.add("Address family", family, 0, 4)
    elif linktype in (12, 101, 228, 229):
        need(data, 0, 1, "Raw IP")
        etype, pos = {4: 0x0800, 6: 0x86DD}.get(data[0] >> 4), 0
    elif linktype in (113, 276):
        layer = p.layer("Linux SLL" if linktype == 113 else "Linux SLL2")
        pos, proto_at = (16, 14) if linktype == 113 else (20, 0)
        need(data, 0, pos, "Linux cooked capture")
        etype = u16(data, proto_at)
        layer.add("Protocol", type_label(etype), proto_at, 2)
    else:
        p.info = f"链路类型 {linktype} · {len(data)} B"
        return
    if etype == 0x0800:
        _ipv4(p, data, pos)
    elif etype == 0x86DD:
        _ipv6(p, data, pos)
    elif etype == 0x0806:
        _arp(p, data, pos)


def _ipv4(p, data, pos):
    layer = p.layer("IPv4")
    need(data, pos, 20, "IPv4")
    ihl = (data[pos] & 15) * 4
    total = u16(data, pos + 2)
    if data[pos] >> 4 != 4 or ihl < 20 or total < ihl:
        raise DecodeIssue("IPv4 首部长度、版本或总长度无效")
    need(data, pos, ihl, "IPv4 options")
    proto = data[pos + 9]
    frag = u16(data, pos + 6)
    p.src, p.dst = addr(data[pos + 12:pos + 16]), addr(data[pos + 16:pos + 20])
    layer.add("Version / IHL", f"4 / {ihl} bytes", pos, 1)
    layer.add("Total length", total, pos + 2, 2)
    layer.add("Identification", f"0x{u16(data, pos + 4):04x}", pos + 4, 2)
    layer.add("Flags / Fragment offset", f"0x{frag:04x}", pos + 6, 2)
    layer.add("TTL", data[pos + 8], pos + 8, 1)
    layer.add("Protocol", f"{proto} ({_IP_PROTO.get(proto, 'Other')})", pos + 9, 1)
    layer.add("Source", p.src, pos + 12, 4)
    layer.add("Destination", p.dst, pos + 16, 4)
    if frag & 0x1fff:
        p.info = f"IPv4 fragment · offset {(frag & 0x1fff) * 8}"
        return
    end = pos + total
    _transport(p, data[:end], pos + ihl, proto, end, fragmented=bool(frag & 0x2000))
    if end > len(data):
        raise DecodeIssue("IPv4 数据报在捕获时被截断")


def _ipv6(p, data, pos):
    layer = p.layer("IPv6")
    need(data, pos, 40, "IPv6")
    if data[pos] >> 4 != 6:
        raise DecodeIssue("IPv6 版本字段无效")
    length = u16(data, pos + 4)
    proto = data[pos + 6]
    p.src, p.dst = addr(data[pos + 8:pos + 24]), addr(data[pos + 24:pos + 40])
    layer.add("Version", 6, pos, 1)
    layer.add("Flow label", f"0x{u32(data, pos) & 0xfffff:05x}", pos, 4)
    layer.add("Payload length", length, pos + 4, 2)
    layer.add("Next header", proto, pos + 6, 1)
    layer.add("Hop limit", data[pos + 7], pos + 7, 1)
    layer.add("Source", p.src, pos + 8, 16)
    layer.add("Destination", p.dst, pos + 24, 16)
    pos += 40
    end = pos + length
    truncated = end > len(data)
    data = data[:end]
    fragmented = False
    while proto in (0, 43, 44, 51, 60):
        need(data, pos, 2, "IPv6 extension")
        if proto == 44:
            size = 8
        elif proto == 51:
            size = (data[pos + 1] + 2) * 4
        else:
            size = (data[pos + 1] + 1) * 8
        need(data, pos, size, "IPv6 extension")
        layer.add("Extension header", f"type {proto}, {size} bytes", pos, size)
        if proto == 44:
            fragment = u16(data, pos + 2)
            if fragment & 0xfff8:
                p.info = f"IPv6 fragment · offset {fragment & 0xfff8}"
                return
            fragmented = bool(fragment & 1)
        proto, pos = data[pos], pos + size
    _transport(p, data, pos, proto, end, fragmented)
    if truncated:
        raise DecodeIssue("IPv6 数据报在捕获时被截断")


def _arp(p, data, pos):
    layer = p.layer("ARP")
    need(data, pos, 8, "ARP")
    hwtype, ptype, hlen, plen, operation = struct.unpack_from("!HHBBH", data, pos)
    need(data, pos + 8, 2 * (hlen + plen), "ARP addresses")
    layer.add("Hardware type", hwtype, pos, 2)
    layer.add("Protocol type", type_label(ptype), pos + 2, 2)
    layer.add("Opcode", operation, pos + 6, 2)
    cursor = pos + 8
    values = []
    for side in ("Sender", "Target"):
        hardware = mac(data[cursor:cursor + hlen])
        cursor += hlen
        raw = data[cursor:cursor + plen]
        address = addr(raw) if (ptype, plen) in ((0x0800, 4), (0x86dd, 16)) else raw.hex()
        layer.add(side + " hardware address", hardware, cursor - hlen, hlen)
        layer.add(side + " protocol address", address, cursor, plen)
        cursor += plen
        values.append((hardware, address))
    p.src, p.dst = values[0][1], values[1][1]
    if operation == 1:
        p.info = f"Who has {p.dst}? Tell {p.src}"
    elif operation == 2:
        p.info = f"{p.src} is at {values[0][0]}"


def _transport(p, data, pos, proto, declared_end, fragmented=False):
    if proto == 6:
        layer = p.layer("TCP")
        need(data, pos, 20, "TCP")
        hlen = (data[pos + 12] >> 4) * 4
        if hlen < 20:
            raise DecodeIssue("TCP 首部长度无效")
        need(data, pos, hlen, "TCP options")
        p.sport, p.dport, p.seq, p.ack = struct.unpack_from("!HHII", data, pos)
        p.flags = ((data[pos + 12] & 1) << 8) | data[pos + 13]
        names = ", ".join(name for bit, name in _TCP_FLAGS if p.flags & bit)
        layer.add("Source port", p.sport, pos, 2)
        layer.add("Destination port", p.dport, pos + 2, 2)
        layer.add("Sequence number", p.seq, pos + 4, 4)
        layer.add("Acknowledgment number", p.ack, pos + 8, 4)
        layer.add("Header length", hlen, pos + 12, 1)
        layer.add("Flags", f"0x{p.flags:03x} [{names}]", pos + 12, 2)
        layer.add("Window", u16(data, pos + 14), pos + 14, 2)
        layer.add("Checksum", f"0x{u16(data, pos + 16):04x}", pos + 16, 2)
        p.payload = data[pos + hlen:]
        p.tcp_payload_len = declared_end - (pos + hlen)
        p.info = f"{p.sport} → {p.dport} [{names}] Seq={p.seq} Len={len(p.payload)}"
        if not fragmented:
            _tcp_application(p, data, pos + hlen)
    elif proto == 17:
        layer = p.layer("UDP")
        need(data, pos, 8, "UDP")
        p.sport, p.dport, length, checksum = struct.unpack_from("!HHHH", data, pos)
        if length < 8:
            raise DecodeIssue("UDP 长度小于首部")
        layer.add("Source port", p.sport, pos, 2)
        layer.add("Destination port", p.dport, pos + 2, 2)
        layer.add("Length", length, pos + 4, 2)
        layer.add("Checksum", f"0x{checksum:04x}", pos + 6, 2)
        p.payload = data[pos + 8:pos + length]
        p.info = f"{p.sport} → {p.dport} Len={len(p.payload)}"
        ports = (p.sport, p.dport)
        if not fragmented and (5353 in ports or 53 in ports):
            _dns(p, p.payload, pos + 8, "mDNS" if 5353 in ports else "DNS")
        if not fragmented and pos + length > len(data):
            raise DecodeIssue("UDP 数据报长度超出捕获范围")
    elif proto in (1, 58):
        name = "ICMP" if proto == 1 else "ICMPv6"
        layer = p.layer(name)
        need(data, pos, 4, name)
        kind, code = data[pos], data[pos + 1]
        labels = ({0: "Echo reply", 8: "Echo request", 3: "Destination unreachable", 11: "Time exceeded"}
                  if proto == 1 else {1: "Destination unreachable", 128: "Echo request", 129: "Echo reply",
                                      133: "Router solicitation", 134: "Router advertisement",
                                      135: "Neighbor solicitation", 136: "Neighbor advertisement"})
        label = labels.get(kind, f"Type {kind}")
        p.info = f"{label} · code {code}"
        layer.add("Type", f"{kind} ({label})", pos, 1)
        layer.add("Code", code, pos + 1, 1)
        layer.add("Checksum", f"0x{u16(data, pos + 2):04x}", pos + 2, 2)
        echoes = (0, 8) if proto == 1 else (128, 129)
        if kind in echoes:
            need(data, pos + 4, 4, name + " echo")
            layer.add("Identifier", u16(data, pos + 4), pos + 4, 2)
            layer.add("Sequence", u16(data, pos + 6), pos + 6, 2)
            p.info += f" · seq={u16(data, pos + 6)}"


def _tcp_application(p, data, pos):
    line = detect_http_line(p.payload)
    if line:
        layer = p.layer("HTTP")
        p.http_line = p.info = line
        layer.add("Start line", line, pos, len(line) + 2)
        words = line.split(" ", 2)
        if line.startswith("HTTP/"):
            layer.add("Status code", words[1], pos + len(words[0]) + 1, len(words[1]))
        else:
            layer.add("Method", words[0], pos, len(words[0]))
            layer.add("Request target", words[1], pos + len(words[0]) + 1, len(words[1]))
    elif 53 in (p.sport, p.dport) and len(p.payload) >= 14:
        n = u16(p.payload, 0)
        if 12 <= n <= len(p.payload) - 2:
            _dns(p, p.payload[2:2+n], pos + 2, "DNS")
    elif len(p.payload) >= 5:
        kind, version, length = struct.unpack_from("!BHH", p.payload)
        kinds = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}
        if kind in kinds and 0x0300 <= version <= 0x0304 and 0 < length <= 18432:
            layer = p.layer("TLS")
            p.info = f"{kinds[kind]} · {length} B"
            layer.add("Content type", f"{kind} ({kinds[kind]})", pos, 1)
            layer.add("Legacy record version", f"0x{version:04x}", pos + 1, 2)
            layer.add("Record length", length, pos + 3, 2)
            hello_types = {1: "Client Hello", 2: "Server Hello"}
            if kind == 22 and length >= 4 and pos + 9 <= len(data):
                hello = data[pos + 5]
                label = hello_types.get(hello, f"Handshake {hello}")
                layer.add("Handshake type", label, pos + 5, 1)
                layer.add("Handshake length", int.from_bytes(data[pos+6:pos+9], "big"), pos + 6, 3)
                p.info = label
                size = int.from_bytes(data[pos + 6:pos + 9], "big")
                if hello in hello_types and size + 4 <= length and pos + 9 + size <= len(data):
                    _tls_hello(layer, data[:pos + 9 + size], pos + 9, hello)


def _tls_hello(layer, data, start, kind):
    # These fields are present only when the entire hello fits in this record.
    need(data, start, 35, "TLS Hello")
    layer.add("Legacy hello version", f"0x{u16(data, start):04x}", start, 2)
    pos = start + 35 + data[start + 34]  # version, random, variable session ID
    if kind == 2:
        need(data, pos, 3, "TLS Server Hello cipher")
        layer.add("Cipher suite", f"0x{u16(data, pos):04x}", pos, 2)
        pos += 3
    else:
        need(data, pos, 2, "TLS Client Hello ciphers")
        pos += 2 + u16(data, pos)
        need(data, pos, 1, "TLS compression methods")
        pos += 1 + data[pos]
    if pos == len(data):  # Extensions are optional for older TLS versions.
        return
    need(data, pos, 2, "TLS extensions")
    end = pos + 2 + u16(data, pos)
    need(data, pos, end - pos, "TLS extensions")
    pos += 2
    while pos < end:
        if pos + 4 > end:
            raise DecodeIssue("TLS 扩展首部截断")
        code, size = struct.unpack_from("!HH", data, pos)
        pos += 4
        if pos + size > end:
            raise DecodeIssue("TLS 扩展长度越界")
        if code == 43 and kind == 2 and size == 2:
            version = u16(data, pos)
            layer.add("Selected version", "TLS 1.3 (0x0304)" if version == 0x304 else f"0x{version:04x}", pos, 2)
        if code == 0 and kind == 1 and size >= 5:
            names_end = pos + 2 + u16(data, pos)
            if names_end > pos + size:
                raise DecodeIssue("TLS SNI 列表越界")
            cursor = pos + 2
            while cursor < names_end:
                if cursor + 3 > names_end:
                    raise DecodeIssue("TLS SNI 首部截断")
                name_type, n = data[cursor], u16(data, cursor + 1)
                cursor += 3
                if cursor + n > names_end:
                    raise DecodeIssue("TLS SNI 名称越界")
                if name_type == 0:
                    layer.add("Server name (SNI)", data[cursor:cursor+n].decode("ascii", "backslashreplace"), cursor, n)
                cursor += n
        pos += size


def _dns_name(msg, offset):
    """Return (expanded name, next offset in original encoding), bounding indirections."""
    parts, seen = [], set()
    cursor, end, wire_length = offset, None, 1
    while True:
        need(msg, cursor, 1, "DNS name")
        if cursor in seen or len(seen) > 255:
            raise DecodeIssue("DNS 名称压缩指针循环或过长")
        seen.add(cursor)
        length = msg[cursor]
        if not length:
            return ".".join(parts) or ".", (end if end is not None else cursor + 1)
        if length & 0xc0 == 0xc0:
            need(msg, cursor, 2, "DNS pointer")
            target = ((length & 0x3f) << 8) | msg[cursor + 1]
            if end is None:
                end = cursor + 2
            cursor = target
            continue
        if length & 0xc0:
            raise DecodeIssue("DNS 标签编码无效")
        need(msg, cursor + 1, length, "DNS label")
        wire_length += length + 1
        if wire_length > 255:
            raise DecodeIssue("DNS 名称超过 255 字节")
        parts.append(msg[cursor + 1:cursor + 1 + length].decode("utf-8", "backslashreplace"))
        cursor += length + 1


def _dns(p, msg, base, name):
    layer = p.layer(name)
    need(msg, 0, 12, name)
    ident, flags, queries, answers, authorities, additional = struct.unpack_from("!6H", msg)
    p.dns_id, p.dns_response = ident, bool(flags & 0x8000)
    layer.add("Transaction ID", f"0x{ident:04x}", base, 2)
    layer.add("Flags", f"0x{flags:04x}", base + 2, 2)
    layer.add("QR", "1 (response)" if p.dns_response else "0 (query)", base + 2, 1)
    counts = (queries, answers, authorities, additional)
    for i, (label, count) in enumerate(zip(("Questions", "Answers", "Authorities", "Additional"), counts)):
        layer.add(label, count, base + 4 + 2*i, 2)
    offset, first_answer = 12, ""
    for index in range(queries):
        item, next_offset = _dns_name(msg, offset)
        need(msg, next_offset, 4, "DNS question")
        qtype = u16(msg, next_offset)
        if index == 0:
            p.dns_question, p.dns_qtype = item, qtype
        layer.add("Query name", item, base + offset, next_offset - offset)
        layer.add("Query type", _DNS_TYPES.get(qtype, qtype), base + next_offset, 2)
        offset = next_offset + 4
    for section, number in zip(("Answer", "Authority", "Additional record"), counts[1:]):
        for _ in range(number):
            owner, after_name = _dns_name(msg, offset)
            need(msg, after_name, 10, "DNS resource record")
            rrtype, rrclass, ttl, size = struct.unpack_from("!HHIH", msg, after_name)
            start = after_name + 10
            need(msg, start, size, "DNS RDATA")
            content = msg[start:start + size]
            value = ""
            if (rrtype, size) in ((1, 4), (28, 16)):
                value = addr(content)
            elif rrtype in (2, 5, 12):
                value, after = _dns_name(msg, start)
                if after > start + size:
                    raise DecodeIssue("DNS 名称超出 RDATA 范围")
            label = _DNS_TYPES.get(rrtype, rrtype)
            if not first_answer:
                first_answer = f"{owner} {label}" + (" " + value if value else "")
            layer.add(section + " name", owner, base + offset, after_name - offset)
            layer.add("Record type", label, base + after_name, 2)
            layer.add("TTL", ttl, base + after_name + 4, 4)
            if value:
                layer.add(str(label), value, base + start, size)
            offset = start + size
    action = "Response" if p.dns_response else "Query"
    summary = p.dns_question or first_answer
    p.info = f"{action} 0x{ident:04x} {summary}"
