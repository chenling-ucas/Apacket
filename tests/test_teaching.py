import struct
import unittest

from packetscope.capture import Frame
from packetscope.session import Session
from packetscope.teaching import StreamLesson


def add(session, seq, ack, flags=0x10, data=b"", *, reverse=False, missing=0, port=443):
    a, b = (bytes([10, 0, 0, 1]), 50000), (bytes([10, 0, 0, 2]), port)
    (src, sport), (dst, dport) = (b, a) if reverse else (a, b)
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 4096, 0, 0)
    total = 40 + len(data) + missing
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 6, 0, src, dst)
    session.append(Frame(len(session.records) / 1000, ip + tcp + data, total, 101))


class TeachingTests(unittest.TestCase):
    def test_handshake_wrap_retry_and_data_on_third_ack(self):
        s = Session()
        add(s, 0xFFFFFFFF, 0, 2)
        add(s, 0xFFFFFFFF, 0, 2)
        add(s, 20, 0, 0x12, reverse=True)
        add(s, 0, 21, data=b"GET /x HTTP/1.1\r\n")
        add(s, 0, 21)
        lesson = StreamLesson(s, 0)
        self.assertIn("#1 SYN → #3 SYN+ACK → #4 ACK", lesson.overview().evidence)
        self.assertIn("3.00 ms", lesson.overview().evidence)
        self.assertIn("最后一次确认", lesson.frame(4).title)
        self.assertIn("读取资源 /x", lesson.frame(4).explanation)
        self.assertNotIn("最后一次", lesson.frame(5).title)

    def test_unmatched_or_missing_handshake_steps(self):
        for bad_packet in ((11, 21, True), (12, 21, False), (11, 22, False)):
            with self.subTest(bad_packet=bad_packet):
                s = Session()
                add(s, 10, 0, 2)
                add(s, 20, 11, 0x12, reverse=True)
                seq, ack, reverse = bad_packet
                add(s, seq, ack, reverse=reverse)
                add(s, 11, 21)  # A later ACK can coincidentally repeat the numbers.
                lesson = StreamLesson(s, 0)
                self.assertNotIn("最后一次", lesson.frame(3).title)
                self.assertNotIn("最后一次", lesson.frame(4).title)
                self.assertNotIn("首末帧相隔", lesson.overview().evidence)
        s = Session()
        add(s, 10, 0, 2)
        add(s, 20, 12, 0x12, reverse=True)
        add(s, 11, 21)
        self.assertNotIn("最后一次", StreamLesson(s, 0).frame(3).title)
        s = Session()
        add(s, 20, 11, 0x12, reverse=True)
        add(s, 11, 21)
        self.assertNotIn("最后一次", StreamLesson(s, 0).frame(2).title)

    def test_http_reassembled_and_live_snapshot_is_stable(self):
        s = Session()
        add(s, 31, 0, 2)
        add(s, 32, 100, data=b"GET /teach")
        before = StreamLesson(s, 0)
        add(s, 42, 100, data=b" HTTP/1.1\r\n")
        add(s, 100, 53, data=b"HTTP/1.1 404 Not Found\r\n", reverse=True)
        after = StreamLesson(s, 0)
        self.assertNotIn("HTTP", before.frame(2).title)
        self.assertNotIn("HTTP", before.overview().explanation)
        for n in (2, 3):
            self.assertIn("拼接", after.frame(n).evidence)
            self.assertIn("读取资源 /teach", after.frame(n).explanation)
        self.assertIn("HTTP 响应 404", after.frame(4).title)
        self.assertIn("HTTP 响应 404", after.overview().explanation)

    def test_midstream_port_443_truncation_fin_reset(self):
        s = Session()
        add(s, 100, 200, data=b"tcp", missing=20)
        add(s, 123, 200, 0x11, b"end")
        add(s, 200, 127, 0x14, reverse=True)
        lesson = StreamLesson(s, 0)
        first = lesson.frame(1)
        self.assertIn("23 字节", first.explanation)
        self.assertIn("载荷 3 字节", first.evidence)
        self.assertIn("20 字节未捕获", first.evidence)
        self.assertIn("期待收到序号 200", first.explanation)
        self.assertNotIn("TLS", lesson.overview().explanation)
        self.assertIn("仍可", lesson.frame(2).explanation)
        self.assertIn("3 字节", lesson.frame(2).explanation)
        self.assertIn("复位", lesson.frame(3).title)
        self.assertIn("#2 A FIN", lesson.overview().evidence)
        self.assertIn("#3 RST", lesson.overview().evidence)
        self.assertIn("2 帧 / 6 字节", lesson.overview().evidence)

    def test_dns_over_tcp_query_answer_and_name_error(self):
        s = Session()
        question = b"\x03lab\x07example\0" + struct.pack("!HH", 1, 1)
        record = b"\xc0\x0c" + struct.pack("!HHIH4B", 1, 1, 60, 4, 192, 0, 2, 2)
        for flags, answer in ((0x100, b""), (0x8180, record), (0x8183, b"")):
            header = struct.pack("!6H", 30, flags, 1, int(bool(answer)), 0, 0)
            msg = header + question + answer
            add(
                s,
                300,
                500,
                data=len(msg).to_bytes(2, "big") + msg,
                reverse=bool(flags & 0x8000),
                port=53,
            )
        lesson = StreamLesson(s, 0)
        self.assertIn("lab.example 的 A 记录", lesson.frame(1).explanation)
        self.assertIn("QR=0", lesson.frame(1).evidence)
        self.assertIn("192.0.2.2", lesson.frame(2).explanation)
        self.assertIn("RCODE=0", lesson.frame(2).evidence)
        self.assertIn("域名不存在", lesson.frame(3).explanation)
        self.assertIn("RCODE=3", lesson.frame(3).evidence)
        self.assertIn("DNS 查询", lesson.overview().explanation)

    def test_tls_header_version_and_encrypted_payload(self):
        s = Session()
        # A TLS 1.3 ServerHello with the legacy record version 0x0303.
        body = (
            bytes.fromhex("0303")
            + bytes(32)
            + bytes.fromhex("00 1301 00 0006 002b 0002 0304")
        )
        hello = b"\x02" + len(body).to_bytes(3, "big") + body
        add(
            s,
            10,
            20,
            data=bytes.fromhex("160303") + len(hello).to_bytes(2, "big") + hello,
        )
        add(s, 10 + 5 + len(hello), 20, data=bytes.fromhex("1703030002aabb"))
        lesson = StreamLesson(s, 0)
        self.assertIn("TLS Server Hello", lesson.frame(1).title)
        self.assertIn("TLS 1.3", lesson.frame(1).explanation)
        self.assertIn("Cipher suite=0x1301", lesson.frame(1).evidence)
        self.assertIn("Application Data", lesson.frame(2).evidence)
        self.assertNotIn("HTTP", lesson.frame(2).explanation)


if __name__ == "__main__":
    unittest.main()
