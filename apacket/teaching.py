"""Explain a captured TCP conversation using its decoded fields and sequence numbers."""

from __future__ import annotations

from dataclasses import dataclass

from .decode import _TCP_FLAGS, Packet
from .session import Record, Session


@dataclass(frozen=True)
class Note:
    title: str
    explanation: str
    evidence: str


def _shown(value: str, limit: int = 100) -> str:
    text = "".join(char if char.isprintable() else " " for char in value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _length(packet: Packet) -> int:
    return (
        len(packet.payload)
        if packet.tcp_payload_len is None
        else packet.tcp_payload_len
    )


def _syn_acks(packet: Packet) -> tuple[int, int]:
    # A peer can accept SYN data (TCP Fast Open), or acknowledge just the SYN.
    after_syn = (packet.seq + 1) & 0xFFFFFFFF
    return after_syn, (after_syn + _length(packet)) & 0xFFFFFFFF


def _match_handshake(records: dict[int, Record]) -> tuple[int, ...]:
    syn = reply = None
    for r in records.values():
        p = r.packet
        source = (p.src, p.sport)
        if p.flags & 0x05:  # RST or FIN ends this establishment attempt.
            syn = reply = None
        elif p.flags & 0x02:
            if not p.flags & 0x10:
                if syn is None or (
                    syn.packet.src,
                    syn.packet.sport,
                    syn.packet.seq,
                ) != (*source, p.seq):
                    syn, reply = r, None
            elif (
                syn
                and source == (syn.packet.dst, syn.packet.dport)
                and p.ack in _syn_acks(syn.packet)
            ):
                reply = r
            else:
                reply = None
        elif reply is not None:
            if (
                p.flags & 0x10
                and source == (syn.packet.src, syn.packet.sport)
                and p.seq == reply.packet.ack
                and p.ack in _syn_acks(reply.packet)
            ):
                return syn.number, reply.number, r.number
            # Once data or another ACK intervenes we cannot identify the third step.
            reply = None
    return ()


def _dns_note(p: Packet, sender: str) -> Note:
    dns = next(layer for layer in p.layers if layer.name == "DNS")
    fields = {f.name: f.value for f in dns.fields}
    title = "DNS 响应" if p.dns_response else "DNS 查询"
    text = f"{sender}返回 DNS 响应。" if p.dns_response else f"{sender}发起 DNS 查询。"
    evidence = [f"DNS ID=0x{p.dns_id:04x}", f"QR={int(p.dns_response)}"]
    if p.dns_question:
        name = _shown(p.dns_question)
        kind = next(f.value for f in dns.fields if f.name == "Query type")
        text += f"查询的是 {name} 的 {kind} 记录。"
        evidence.extend((f"Query name={name}", f"Query type={kind}"))
    if p.dns_response:
        rcode = int(fields["Flags"], 16) & 0xF
        evidence.append(f"DNS 首部 RCODE={rcode}")
        if rcode in (2, 3, 5):
            text += {
                2: "服务器报告处理失败。",
                3: "服务器报告该域名不存在。",
                5: "服务器拒绝了查询。",
            }[rcode]
        owner = None
        for field in dns.fields:
            if field.name == "Answer name":
                owner = _shown(field.value)
            elif field.name in ("Authority name", "Additional record name"):
                break
            elif owner is not None and field.name in (
                "A",
                "AAAA",
                "CNAME",
                "NS",
                "PTR",
            ):
                value = _shown(field.value)
                text += f"应答区给出 {owner} 的 {field.name} 记录 {value}。"
                evidence.append(f"{field.name}={value}")
                break
    return Note(title, text, "，".join(evidence))


def application_note(
    p: Packet, http_line: str, sender: str = "发送方"
) -> tuple[str, Note] | None:
    """Return an observed application event category and its teaching note, if decoded."""
    if http_line:
        words = http_line.split(" ", 2)
        if http_line.startswith("HTTP/"):
            key, title = "response", f"HTTP 响应 {words[1]}"
            categories = {
                "1": "这是临时响应",
                "2": "服务器已接受这次请求",
                "3": "客户端需要根据响应继续处理",
                "4": "服务器判定这次请求无法完成",
                "5": "服务器处理请求时遇到错误",
            }
            meanings = {
                "200": "服务器报告请求成功",
                "202": "服务器已接受请求，处理可以稍后完成",
                "204": "请求成功，响应中没有消息正文",
                "304": "客户端可沿用缓存的内容",
                "401": "请求需要有效的身份凭据",
                "403": "服务器拒绝了这次访问",
                "404": "服务器报告没有找到请求的资源",
            }
            explanation = f"{sender}返回 HTTP {words[1]}。{meanings.get(words[1], categories[words[1][0]])}。"
        else:
            key, title = "request", f"HTTP {words[0]} 请求"
            target = _shown(words[1])
            if words[0] == "GET":
                explanation = f"{sender}请求读取资源 {target}。"
            elif words[0] == "POST":
                explanation = f"{sender}向 {target} 提交数据，请对方处理。"
            else:
                explanation = f"{sender}对 {target} 发出 {words[0]} 请求。"
        source = (
            "本帧可读的 HTTP 首行"
            if p.http_line == http_line
            else "按 TCP 序号拼接后读到的 HTTP 首行"
        )
        return key, Note(title, explanation, f"{source}　{_shown(http_line)}")
    if "DNS" in p.protocols and p.dns_response is not None:
        note = _dns_note(p, sender)
        return note.title, note
    tls = next((layer for layer in p.layers if layer.name == "TLS"), None)
    if tls is None:
        return None
    fields = {f.name: f.value for f in tls.fields}
    kind = fields["Content type"]
    hello = fields.get("Handshake type")
    evidence = f"TLS Content type={kind}"
    if hello:
        evidence += f"，Handshake type={hello}"
    if hello == "Client Hello":
        title = "TLS Client Hello"
        explanation = "客户端发起 TLS 协商，向对方提供可用的加密参数。"
        if "Server name (SNI)" in fields:
            name = _shown(fields["Server name (SNI)"])
            explanation += f"它在 SNI 字段填写的服务名是 {name}。"
            evidence += f"，SNI={name}"
    elif hello == "Server Hello":
        title = "TLS Server Hello"
        explanation = "服务端回复 TLS 握手参数。"
        if "Selected version" in fields:
            version = fields["Selected version"]
            explanation += f"它选择的协议版本是 {version}。"
            evidence += f"，Selected version={version}"
        if "Cipher suite" in fields:
            evidence += f'，Cipher suite={fields["Cipher suite"]}'
    elif kind.startswith("23 "):
        title = "TLS 加密记录"
        explanation = "记录头标为 Application Data。加密内容里可能有应用消息，也可能有 TLS 握手等控制消息。"
    elif kind.startswith("22 "):
        title, explanation = "TLS 握手记录", "这段记录承载 TLS 握手消息。"
    elif kind.startswith("21 "):
        title, explanation = (
            "TLS 告警记录",
            "发送方通过 TLS 告警通知对方一个状态或错误。",
        )
    else:
        title = "TLS 密码状态切换记录"
        explanation = "早期 TLS 用它通知对方启用协商的密码参数。TLS 1.3 也允许为兼容而发送这条记录。"
    return title, Note(title, explanation, evidence)


class StreamLesson:
    """Snapshot the stream and its current reassembly results when a view opens."""

    def __init__(self, session: Session, sid: int):
        stream = session.analysis.streams[sid]
        self._sid = sid
        self._left = stream.left
        self._records = {n: session.records[n - 1] for n in stream.frames}
        self._http = {
            n: session.analysis.meta[n].http_line or r.packet.http_line
            for n, r in self._records.items()
        }
        self._pieces: dict[tuple[str, str], list[int]] = {}
        for n, r in self._records.items():
            if line := session.analysis.meta[n].http_line:
                sender, _ = self._ends(r.packet)
                self._pieces.setdefault((sender, line), []).append(n)
        self._handshake = _match_handshake(self._records)
        self._summary = self._summarize()

    def _ends(self, p: Packet) -> tuple[str, str]:
        return ("A", "B") if (p.src, p.sport) == self._left else ("B", "A")

    def _http_frames(self, number: int, sender: str) -> str:
        line = self._http[number]
        pieces = self._pieces.get((sender, line), ())
        if number not in pieces or len(pieces) < 2:
            return f"#{number}"
        shown = "、".join(f"#{n}" for n in pieces[:4])
        return shown if len(pieces) <= 4 else f"{shown} 等 {len(pieces)} 帧"

    def _summarize(self) -> Note:
        counts = {"A": 0, "B": 0}
        payloads = {"A": 0, "B": 0}
        first_data = None
        syns = {}
        apps = {}
        ends = {}
        for n, r in self._records.items():
            p = r.packet
            sender, peer = self._ends(p)
            counts[sender] += 1
            payloads[sender] += len(p.payload)
            if first_data is None and _length(p) > 0:
                first_data = n
            if p.flags & 2:
                syns.setdefault("SYN+ACK" if p.flags & 16 else "SYN", n)
            if p.flags & 4:
                ends.setdefault("RST", n)
            elif p.flags & 1:
                ends.setdefault(f"{sender} FIN", n)
            if p.payload and (event := application_note(p, self._http[n])):
                key, note = event
                if key not in apps:
                    refs = self._http_frames(n, sender) if self._http[n] else f"#{n}"
                    apps[key] = (refs, f"{sender} → {peer}", note)

        explanation = []
        evidence = []
        if self._handshake:
            one, two, three = self._handshake
            sender, peer = self._ends(self._records[one].packet)
            explanation.append(
                f"{sender} 发起 TCP 连接，{peer} 回应，{sender} 再确认。双方由此知道各自从哪个序号开始。"
            )
            leg = f"#{one} SYN → #{two} SYN+ACK → #{three} ACK"
            elapsed = (
                self._records[three].frame.timestamp
                - self._records[one].frame.timestamp
            )
            if elapsed >= 0:
                leg += f"（首末帧相隔 {elapsed * 1000:.2f} ms）"
            evidence.append(leg)
        elif syns:
            explanation.append(
                "抓到了建立连接时的报文，这段记录中未找到方向和序号都能对上的完整三次握手。"
            )
            evidence.append("、".join(f"#{n} {kind}" for kind, n in syns.items()))
        else:
            first = next(iter(self._records))
            explanation.append(
                f"这段捕获从 #{first} 开始，其中没有建立 TCP 连接时的 SYN。"
            )

        for refs, direction, note in apps.values():
            explanation.append(f"{refs} {direction}　{note.title}。{note.explanation}")
        if not apps and first_data is not None:
            p = self._records[first_data].packet
            sender, peer = self._ends(p)
            explanation.append(
                f"#{first_data} 中 {sender} 向 {peer} 发送了 {_length(p)} 字节的 TCP 载荷。"
                "可见字段尚不足以识别具体的应用消息。"
            )
        if ends:
            for kind, n in ends.items():
                explanation.append(
                    f"#{n} 的发送方要求复位连接。"
                    if kind == "RST"
                    else f"#{n} 的 {kind[0]} 端发出 FIN，表示自己这一侧发完了。"
                )
            evidence.append("、".join(f"#{n} {kind}" for kind, n in ends.items()))
        evidence.append(
            "本次捕获（按帧累计 TCP 载荷）\n"
            f'A → B　{counts["A"]} 帧 / {payloads["A"]} 字节\n'
            f'B → A　{counts["B"]} 帧 / {payloads["B"]} 字节'
        )
        return Note(
            f"TCP 流 #{self._sid} 的通信过程",
            "\n".join(explanation),
            "\n".join(evidence),
        )

    def overview(self) -> Note:
        return self._summary

    def frame(self, number: int) -> Note:
        r = self._records[number]
        p = r.packet
        sender, peer = self._ends(p)
        flags = "+".join(name for mask, name in _TCP_FLAGS if p.flags & mask) or "无"
        evidence = [f"#{number}　{sender} → {peer}　{flags}　Seq={p.seq}"]
        if p.flags & 16:
            evidence[0] += f"　Ack={p.ack}"
        captured, declared = len(p.payload), _length(p)
        evidence[0] += f"　已捕获载荷 {captured} 字节"
        if declared > captured:
            evidence.append(
                f"首部给出的载荷长度为 {declared} 字节，其中 {declared - captured} 字节未捕获。"
            )

        ack_text = f"{sender} 告诉 {peer}，接下来期待收到序号 {p.ack}。"
        if p.flags & 4:
            title, text = "TCP 连接复位（RST）", f"{sender} 要求立即复位这条连接。"
        elif p.flags & 2:
            if p.flags & 16:
                title = "回应连接请求（SYN+ACK）"
                text = f"{sender} 发来自己的起始序号 {p.seq}，并用确认号 {p.ack} 告诉对方下一步期待的序号。"
            else:
                title = "发起连接（SYN）"
                text = (
                    f"{sender} 请求和 {peer} 建立连接，并报出自己的起始序号 {p.seq}。"
                )
        elif number in self._handshake:
            title = "三次握手的最后一次确认"
            previous = self._records[self._handshake[1]].packet
            text = f"{sender} 用 ACK 确认了 #{self._handshake[1]} 中 {peer} 的 SYN。"
            if p.ack == (previous.seq + 1) & 0xFFFFFFFF:
                text += f"SYN 占一个序号，对方从 {previous.seq} 起步，因此这里填 Ack={p.ack}。"
        elif p.flags & 1:
            title = "结束一个方向的发送（FIN）"
            text = f"{sender} 表示本方向的字节已经发完，{peer} 仍可向它发送数据。"
        elif declared > 0:
            title, text = (
                "传送 TCP 数据",
                f"{sender} 向 {peer} 传送 {declared} 字节的 TCP 载荷。",
            )
        elif p.flags & 16:
            title, text = "TCP 确认（ACK）", ack_text
        else:
            title, text = (
                "TCP 控制报文",
                f"{sender} 向 {peer} 发送了没有载荷的 TCP 段。",
            )

        if number in self._handshake:
            one, two, three = self._handshake
            evidence.append(f"握手帧　#{one} SYN → #{two} SYN+ACK → #{three} ACK")
        if declared > 0 and (p.flags & 0x07 or number in self._handshake):
            text += f" 这一帧同时携带 {declared} 字节的 TCP 载荷。"
        if (
            p.flags & 16
            and declared > 0
            and not p.flags & 2
            and number not in self._handshake
        ):
            text += " " + ack_text

        if event := application_note(p, self._http[number]):
            _, note = event
            if not p.flags & 0x07 and number not in self._handshake:
                title = note.title
            text += " " + note.explanation
            evidence.append(note.evidence)
            if self._http[number] and not p.http_line:
                evidence.append(
                    f"参与首行重组的帧　{self._http_frames(number, sender)}"
                )
        return Note(title, text, "\n".join(evidence))
