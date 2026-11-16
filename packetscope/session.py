"""Capture records, derived conversations, and display-filter expressions."""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass

from .analysis import Analyzer
from .decode import decode


@dataclass
class Record:
    number: int
    frame: object
    packet: object


class Session:
    def __init__(self):
        self.records = []
        self.analysis = Analyzer()
        self.owners = {}  # stream id -> endpoint -> observed process
        self.live = False
        self.name = ""
        self.stored_bytes = 0

    def append(self, frame):
        packet = decode(frame.data, frame.linktype)
        number = len(self.records) + 1
        self.analysis.add(number, frame.timestamp, packet)
        self.records.append(Record(number, frame, packet))
        self.stored_bytes += len(frame.data)

    def highest(self, record):
        return (
            "HTTP"
            if self.analysis.meta[record.number].http_line
            else record.packet.protocol
        )

    def summary(self, record):
        meta = self.analysis.meta[record.number]
        return meta.http_line or record.packet.info


PROTOCOLS = {
    "ethernet",
    "ipv4",
    "ipv6",
    "tcp",
    "udp",
    "http",
    "tls",
    "icmp",
    "icmpv6",
    "arp",
    "dns",
    "mdns",
    "vlan",
    "raw",
    "loopback",
}
ALIASES = {"ip": "ipv4", "ip6": "ipv6", "icmp6": "icmpv6"}
FIELDS = {
    "ip.addr",
    "ip.src",
    "ip.dst",
    "tcp.port",
    "udp.port",
    "tcp.stream",
    "frame.number",
    "process",
    "info",
}


def display_predicate(text):
    """Compile a small explicit display-filter grammar; never evaluate user code."""
    if not text.strip():
        return lambda session, record: True
    lex = shlex.shlex(text, posix=True, punctuation_chars="()=!&|")
    lex.whitespace_split = True
    lex.commenters = ""
    tokens = []
    for word in lex:
        if word and set(word) <= set("()=!&|"):
            tokens.extend(re.findall(r"==|!=|&&|\|\||.", word))
        else:
            tokens.append(word)
    at = 0

    def peek():
        return tokens[at].casefold() if at < len(tokens) else ""

    def pop():
        nonlocal at
        if at == len(tokens):
            raise ValueError("表达式不完整")
        value = tokens[at]
        at += 1
        return value

    def atom():
        key = pop().casefold()
        if key in ("not", "!"):
            inner = atom()
            return lambda s, r: not inner(s, r)
        if key == "(":
            inner = parse_or()
            if pop() != ")":
                raise ValueError("缺少右括号")
            return inner
        if key in ALIASES:
            key = ALIASES[key]
        if key in PROTOCOLS:
            return lambda s, r: key == s.highest(r).casefold() or any(
                key == p.casefold() for p in r.packet.protocols
            )
        if key not in FIELDS:
            raise ValueError("未知协议或字段：" + key)
        op = pop().casefold()
        if op not in ("==", "!=", "contains"):
            raise ValueError("字段支持 ==、!= 或 contains")
        val = pop().casefold()
        if key in ("tcp.port", "udp.port", "tcp.stream", "frame.number"):
            if not val.isdecimal() or op == "contains":
                raise ValueError("数字字段需要用 == 或 != 比较整数")
            val = str(int(val))

        def matches(s, r):
            p = r.packet
            if key.startswith("ip."):
                if "IPv4" not in p.protocols and "IPv6" not in p.protocols:
                    return False
                values = {
                    "ip.addr": (p.src, p.dst),
                    "ip.src": (p.src,),
                    "ip.dst": (p.dst,),
                }[key]
            elif key.endswith(".port"):
                if key.split(".")[0].upper() not in p.protocols:
                    return False
                values = (p.sport, p.dport)
            elif key == "frame.number":
                values = (r.number,)
            elif key == "info":
                values = (s.summary(r),)
            else:
                stream = s.analysis.meta[r.number].stream
                if stream is None:
                    return False
                values = (
                    (stream,)
                    if key == "tcp.stream"
                    else tuple(s.owners.get(stream, {}).values())
                )
                if not values:
                    return False
            found = any(
                (
                    val in str(v).casefold()
                    if op == "contains"
                    else val == str(v).casefold()
                )
                for v in values
            )
            return not found if op == "!=" else found

        return matches

    def parse_and():
        group = [atom()]
        while peek() in ("and", "&&"):
            pop()
            group.append(atom())
        return lambda s, r: all(f(s, r) for f in group)

    def parse_or():
        group = [parse_and()]
        while peek() in ("or", "||"):
            pop()
            group.append(parse_and())
        return lambda s, r: any(f(s, r) for f in group)

    result = parse_or()
    if at != len(tokens):
        raise ValueError("无法识别：" + " ".join(tokens[at:]))
    return result
