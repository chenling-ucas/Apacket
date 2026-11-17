import struct
import unittest

from apacket.decode import decode


def ipv4(proto, content, options=b"", extra=b"", frag=0):
    total = 20 + len(options) + len(content)
    head = struct.pack("!BBHHHBBH4s4s", 0x45 + len(options) // 4, 0, total,
                       0x1200, frag, 64, proto, 0, b"\x0a\x00\x00\x04", b"\x0a\x00\x00\x05")
    return head + options + content + extra


def tcp(data):
    return struct.pack("!HHIIBBHHH", 2345, 8000, 123, 321, 0x50, 0x18, 1024, 0, 0) + data


def udp(source, destination, data):
    return struct.pack("!4H", source, destination, len(data) + 8, 0) + data


class DecoderTests(unittest.TestCase):
    def test_field_highlight_accounts_for_vlan_and_ip_options(self):
        msg = b"GET /sample HTTP/1.1\r\nHost: localhost\r\n\r\n"
        frame = bytes(12) + bytes.fromhex("8100000a0800") + ipv4(6, tcp(msg), options=bytes(4))
        packet = decode(frame, 1)
        self.assertEqual(packet.protocols, ["Ethernet", "VLAN", "IPv4", "TCP", "HTTP"])
        self.assertEqual(packet.info, "GET /sample HTTP/1.1")
        port = next(f for layer in packet.layers for f in layer.fields if f.name == "Destination port")
        self.assertEqual(frame[port.start:port.start + port.size], (8000).to_bytes(2, "big"))
        self.assertEqual(packet.problem, "")

    def test_padding_is_not_application_data(self):
        padding = b"GET /bad HTTP/1.1\r\n"
        packet = decode(ipv4(6, tcp(b""), extra=padding), 101)
        self.assertEqual(packet.protocol, "TCP")
        self.assertFalse(packet.payload)
        self.assertEqual(packet.tcp_payload_len, 0)

    def test_dns_pointer_in_answer_preserves_owner_and_address(self):
        question = b"\x04host\x07example\x00" + struct.pack("!HH", 1, 1)
        header = struct.pack("!6H", 1337, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 120, 4) + bytes([192, 0, 2, 1])
        frame = ipv4(17, udp(53, 50101, header + question + answer))
        packet = decode(frame, 101)
        self.assertEqual((packet.protocol, packet.dns_id, packet.dns_response, packet.dns_question),
                         ("DNS", 1337, True, "host.example"))
        field = next(f for f in packet.layers[-1].fields if f.name == "A")
        self.assertEqual(field.value, "192.0.2.1")
        self.assertEqual(frame[field.start:field.start+field.size], bytes([192, 0, 2, 1]))

    def test_bad_dns_pointer_is_reported(self):
        circular = struct.pack("!6H", 7, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        p = decode(ipv4(17, udp(10001, 53, circular)), 101)
        self.assertEqual(p.protocol, "DNS")
        self.assertIn("指针", p.problem)

    def test_truncated_data_and_ip_fragment(self):
        decoy = b"GET / HTTP/1.1\r\n"
        frame = bytes(12) + b"\x08\x00" + ipv4(6, tcp(decoy))
        for count in range(len(frame)):
            with self.subTest(captured=count):
                p = decode(frame[:count], 1)
                self.assertTrue(p.problem)
                self.assertTrue(all(f.start + f.size <= count for layer in p.layers for f in layer.fields))
        self.assertEqual(decode(ipv4(6, tcp(decoy), frag=1), 101).protocol, "IPv4")

    def test_icmp_on_loopback_either_byte_order(self):
        echo = bytes.fromhex("0800000012340001")
        for header in (b"\x02\0\0\0", b"\0\0\0\x02"):
            p = decode(header + ipv4(1, echo), 0)
            self.assertEqual(p.protocol, "ICMP")
            self.assertIn("Echo request", p.info)

    def test_ipv6_extension_advances_before_udp(self):
        segment = udp(12345, 43210, b"hello")
        ext = bytes([17, 0, 0, 0, 0, 0, 0, 0])
        prefix = struct.pack("!IHBB", 6 << 28, len(segment) + len(ext), 0, 64) + bytes(15) + b"\x01"
        p = decode(prefix + bytes(15) + b"\x02" + ext + segment, 101)
        self.assertEqual((p.src, p.dst, p.sport, p.dport), ("::1", "::2", 12345, 43210))
        self.assertEqual(p.payload, b"hello")


if __name__ == "__main__":
    unittest.main()
