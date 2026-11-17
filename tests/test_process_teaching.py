import unittest

from apacket.decode import Packet
from apacket.process_teaching import endpoint_note, process_note
from apacket.session import Record, Session

CLIENT = ("127.0.0.1", 53000)
SERVER = ("127.0.0.1", 443)
OWNER = "python (PID 210)"


def add(session, source, target, *, flags=0x10, seq=1, ack=1, payload=b"", hello=False):
    number = len(session.records) + 1
    packet = Packet(
        src=source[0],
        sport=source[1],
        dst=target[0],
        dport=target[1],
        protocols=["TCP"],
        flags=flags,
        seq=seq,
        ack=ack,
        payload=payload,
    )
    if hello:
        layer = packet.layer("TLS")
        layer.add("Content type", "22 (Handshake)", 0, 1)
        layer.add("Handshake type", "Client Hello", 5, 1)
        layer.add("Server name (SNI)", "class.example", 72, 13)
    session.analysis.add(number, number, packet)
    session.records.append(Record(number, None, packet))


class ProcessTeachingTests(unittest.TestCase):
    def test_one_process_owns_both_ends_of_one_connection(self):
        s = Session()
        add(s, CLIENT, SERVER, flags=0x02, seq=10)
        add(s, SERVER, CLIENT, flags=0x12, seq=50, ack=11)
        add(s, CLIENT, SERVER, seq=11, ack=51, payload=b"GET /chap")
        add(s, CLIENT, SERVER, seq=20, ack=51, payload=b"ter HTTP/1.1\r\n")
        s.owners[0] = {CLIENT: OWNER, SERVER: OWNER}
        overall = process_note(s, OWNER)
        self.assertIn("1 条 TCP 流", overall.explanation)
        self.assertIn("共捕获 4 帧", overall.explanation)
        self.assertIn("发出 4 帧，收到 4 帧", overall.explanation)
        self.assertIn("4 帧在这个进程自己的端点间", overall.explanation)
        self.assertIn("端口 53000 向自己的端口 443", overall.explanation)

        client = endpoint_note(s, 0, CLIENT, OWNER)
        server = endpoint_note(s, 0, SERVER, OWNER)
        self.assertIn("本地端点向对端主动请求", client.explanation)
        self.assertIn("对端向本地端点主动请求", server.explanation)
        self.assertIn("发出 1 帧，收到 3 帧", server.explanation)
        self.assertIn("对端请求读取", server.explanation)
        self.assertIn("本机请求读取", client.explanation)
        self.assertIn("/chapter", client.explanation)
        self.assertIn("第 3 帧", server.evidence)
        self.assertIn("拼接", server.evidence)

    def test_endpoint_shows_http_in_both_directions_even_when_capture_starts_with_response(
        self,
    ):
        s = Session()
        add(s, SERVER, CLIENT, payload=b"HTTP/1.1 200 OK\r\n")
        add(s, CLIENT, SERVER, payload=b"GET /next HTTP/1.1\r\n")
        s.owners = {0: {CLIENT: OWNER}}
        local = endpoint_note(s, 0, CLIENT, OWNER)
        self.assertIn("对端返回 HTTP 200", local.explanation)
        self.assertIn("本机请求读取", local.explanation)
        self.assertIn("/next", local.explanation)
        self.assertIn("第 1 帧", local.evidence)
        self.assertIn("第 2 帧", local.evidence)
        self.assertNotIn("/next", process_note(s, OWNER).explanation)

    def test_decoded_tcp_dns_fields_are_used(self):
        s = Session()
        add(s, CLIENT, SERVER, payload=b"DNS")
        packet = s.records[0].packet
        layer = packet.layer("DNS")
        layer.add("Query type", "A", 24, 2)
        packet.dns_response, packet.dns_question, packet.dns_id = (
            False,
            "class.example",
            45,
        )
        s.owners = {0: {CLIENT: OWNER}}
        local = endpoint_note(s, 0, CLIENT, OWNER)
        self.assertIn("DNS 查询", local.explanation)
        self.assertIn("class.example", local.explanation)
        self.assertIn("DNS ID=0x002d", local.evidence)

    def test_no_application_guessed_from_peer_port_on_partial_connection(self):
        s = Session()
        add(s, SERVER, CLIENT, payload=b"opaque", seq=200)
        s.owners[0] = {CLIENT: OWNER, SERVER: "other (PID 120)"}
        local = endpoint_note(s, 0, CLIENT, OWNER)
        self.assertIn("谁先发起 TCP 连接未知", local.explanation)
        self.assertIn("0 帧，收到 1 帧", local.explanation)
        self.assertIn("捕获到 6 字节 TCP 载荷", local.explanation)
        self.assertNotIn("TLS", local.explanation)
        self.assertNotIn("HTTP", local.explanation)
        self.assertIn("第 1 帧", local.evidence)
        self.assertNotIn("自己的端点", process_note(s, OWNER).explanation)

    def test_count_distinct_streams_and_use_direction_of_tls_message(self):
        s = Session()
        add(s, CLIENT, SERVER, flags=0x02)
        second_client = (CLIENT[0], 53222)
        add(s, second_client, SERVER, hello=True, payload=b"tls")
        s.owners = {0: {SERVER: OWNER}, 1: {SERVER: OWNER}}
        note = process_note(s, OWNER)
        self.assertIn("2 条 TCP 流", note.explanation)
        self.assertIn("发出 0 帧，收到 2 帧", note.explanation)
        self.assertIn("对端向本地端点发送了 TLS Client Hello", note.explanation)
        self.assertIn("class.example", note.explanation)
        self.assertIn("流 #1 第 2 帧", note.evidence)
        self.assertIn("本机 TCP 连接表", note.evidence)
        self.assertIn("两端的 IP 地址和端口", note.evidence)

    def test_midstream_ack_only_provides_a_concrete_action(self):
        s = Session()
        add(s, CLIENT, SERVER, ack=9901)
        s.owners = {0: {SERVER: OWNER}}
        note = endpoint_note(s, 0, SERVER, OWNER)
        self.assertIn("对端向本地端点发出确认", note.explanation)
        self.assertIn("确认号为 9901", note.evidence)
        self.assertIn("发起 TCP 连接未知", note.explanation)

    def test_syn_ack_without_original_syn_is_a_reply(self):
        s = Session()
        add(s, SERVER, CLIENT, flags=0x12)
        s.owners = {0: {SERVER: OWNER}}
        note = endpoint_note(s, 0, SERVER, OWNER)
        self.assertIn("本地端点向对端回应", note.explanation)
        self.assertIn("SYN、ACK", note.evidence)


if __name__ == "__main__":
    unittest.main()
