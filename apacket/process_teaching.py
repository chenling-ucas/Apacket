"""Explain observed TCP traffic from the selected local process or socket's perspective."""

from __future__ import annotations

from dataclasses import dataclass

from .analysis import Endpoint
from .teaching import Note, application_note


@dataclass(frozen=True)
class _Event:
    text: str
    evidence: str
    priority: int


@dataclass
class _Traffic:
    sent: int = 0
    received: int = 0
    internal: int = 0
    opening: _Event | None = None
    example: _Event | None = None
    reverse_http: _Event | None = None


def _address(ep: Endpoint) -> str:
    host, port = ep
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _application(packet, http_line, actor, subject, witness):
    event = application_note(packet, http_line, sender=subject)
    if event is None:
        return None
    kind, note = event
    evidence = f"{witness}。{note.evidence}"
    if http_line:
        return _Event(note.explanation, evidence, 4)
    if kind in ("DNS 查询", "DNS 响应"):
        return _Event(note.explanation, evidence, 3)
    priority = 3 if kind in ("TLS Client Hello", "TLS Server Hello") else 2
    return _Event(f"{actor}发送了 {note.title}。{note.explanation}", evidence, priority)


def _scan(session, stream, owned, *, both_http_directions=False):
    observed = _Traffic()
    reverse_http_key = None
    for number in stream.frames:
        packet = session.records[number - 1].packet
        src, dst = (packet.src, packet.sport), (packet.dst, packet.dport)
        sent, received = src in owned, dst in owned
        observed.sent += sent
        observed.received += received
        observed.internal += sent and received
        flags = packet.flags
        opening = (flags & 0x07) == 0x02
        priority = observed.example.priority if observed.example else -1
        http_line = session.analysis.meta[number].http_line or packet.http_line
        http_key = (src, http_line.startswith("HTTP/")) if http_line else None
        want_reverse = http_key is not None and http_key == reverse_http_key
        has_dns = "DNS" in packet.protocols and packet.dns_response is not None
        has_application = (http_line and (priority < 4 or want_reverse)) or (
            priority < 3 and ("TLS" in packet.protocols or has_dns)
        )
        has_payload = priority < 1 and packet.payload
        control = priority < 0 and not opening and (flags & 0x15)
        if not (opening or has_application or has_payload or control):
            continue
        if sent and received:
            actor = subject = f"进程的端口 {src[1]} 向自己的端口 {dst[1]}"
        elif sent:
            actor, subject = "本地端点向对端", "本机"
        else:
            actor, subject = "对端向本地端点", "对端"
        witness = f"流 #{stream.id} 第 {number} 帧，{_address(src)} → {_address(dst)}"
        if opening:
            if not flags & 0x10:
                if observed.opening is None or observed.opening.priority < 2:
                    observed.opening = _Event(
                        f"{actor}主动请求建立 TCP 连接。",
                        f"{witness}，SYN 已置位、ACK 未置位。",
                        2,
                    )
            elif observed.opening is None:
                observed.opening = _Event(
                    f"{actor}回应了建立 TCP 连接的请求。",
                    f"{witness}，标志含 SYN、ACK。",
                    1,
                )
        example = None
        if has_application:
            example = _application(packet, http_line, actor, subject, witness)
            if want_reverse:
                observed.reverse_http = example
                reverse_http_key = None
            elif both_http_directions and http_key:
                reverse_http_key = (dst, not http_key[1])
        if example is None and has_payload:
            example = _Event(
                f"{actor}发送了数据，该帧捕获到 {len(packet.payload)} 字节 TCP 载荷。",
                f"{witness}，TCP 头之后有 {len(packet.payload)} 字节。",
                1,
            )
        if example is None and control:
            if flags & 0x04:
                action, field = "发出 RST，要求立即复位连接", "RST"
            elif flags & 0x01:
                action, field = "发出 FIN，表示自己准备结束发送", "FIN"
            else:
                action = f"发出确认，表示接下来期望收到序号为 {packet.ack} 的数据"
                field = f"ACK，确认号为 {packet.ack}"
            example = _Event(
                f"{actor}{action}。", f"{witness}，TCP 标志含 {field}。", 0
            )
        if example and (
            not observed.example or example.priority > observed.example.priority
        ):
            observed.example = example
    return observed


def process_note(session, owner) -> Note:
    streams = frames = sent = received = internal = 0
    example = None
    for sid, ownership in session.owners.items():
        owned = {ep for ep, name in ownership.items() if name == owner}
        if not owned:
            continue
        stream = session.analysis.streams[sid]
        traffic = _scan(session, stream, owned)
        streams += 1
        frames += len(stream.frames)
        sent += traffic.sent
        received += traffic.received
        internal += traffic.internal
        for candidate in (traffic.example, traffic.opening):
            if candidate and (not example or candidate.priority > example.priority):
                example = candidate

    title = f"{owner} 的 TCP 通信"
    if not streams:
        return Note(
            title,
            "当前没有与该进程匹配的 TCP 流。",
            "进程归属取自抓包时的本机 TCP 连接表。",
        )
    summary = f"抓包期间，{streams} 条 TCP 流与这个本机进程匹配，共捕获 {frames} 帧。该进程的端点发出 {sent} 帧，收到 {received} 帧。"
    if internal:
        summary += (
            f"其中 {internal} 帧在这个进程自己的端点间传递，在收发两项中各计一次。"
        )
    evidence = (
        "抓包时，本机 TCP 连接表记录了本地端点所属的 PID。程序用两端的 IP 地址和端口匹配抓到的 TCP 流。"
    )
    if example:
        summary += "\n" + example.text
        evidence += "\n" + example.evidence
    return Note(title, summary, evidence)


def endpoint_note(session, sid, local_ep, owner) -> Note:
    stream = session.analysis.streams[sid]
    other = stream.right if local_ep == stream.left else stream.left
    observed = _scan(session, stream, {local_ep}, both_http_directions=True)
    title = f"流 #{sid} · {owner} 的本地端点"
    summary = (
        f"{owner} 使用 {_address(local_ep)} 与 {_address(other)} 通信。"
        f"本地端点发出 {observed.sent} 帧，收到 {observed.received} 帧。"
    )
    evidence = (
        f"在抓包时的本机 TCP 连接表中，本地端点 {_address(local_ep)} 与上述对端之间的连接属于该进程。"
    )
    if observed.opening:
        summary += "\n" + observed.opening.text
        evidence += "\n" + observed.opening.evidence
    else:
        summary += "\n这段抓包没有记录建连的 SYN 或 SYN、ACK，谁先发起 TCP 连接未知。"
    for event in (observed.example, observed.reverse_http):
        if event:
            summary += "\n" + event.text
            evidence += "\n" + event.evidence
    return Note(title, summary, evidence)
