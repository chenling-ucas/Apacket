import os
import socket
import sys
import unittest
from types import SimpleNamespace

from packetscope.analysis import Analyzer
from packetscope.processes import snapshot


def pkt(src='127.0.0.1', dst='127.0.0.1', sport=53000, dport=8000, **kwargs):
    values = dict(src=src, dst=dst, sport=sport, dport=dport, protocols=['TCP'],
                  flags=0x10, seq=0, ack=0, payload=b'',
                  dns_id=None, dns_response=None, dns_question='', dns_qtype=None)
    values.update(kwargs)
    return SimpleNamespace(**values)


class FlowTests(unittest.TestCase):
    def test_out_of_order_wraparound_and_retry(self):
        a = Analyzer()
        a.add(1, 0, pkt(seq=0xfffffff9, flags=2))
        a.add(2, .1, pkt(seq=0xfffffff9, flags=2))  # retransmitted SYN
        a.add(3, .2, pkt(seq=0, payload=b' HTTP/1.1\r\n'))
        a.add(4, .3, pkt(seq=0, payload=b' HTTP/1.1\r\n'))
        a.add(5, .4, pkt(seq=0xfffffffa, payload=b'GET /x'))
        self.assertEqual(len(a.streams), 1)
        self.assertEqual(a.streams[0].http_events, [(5, 'GET /x HTTP/1.1')])
        self.assertEqual(a.meta[3].http_line, a.meta[5].http_line)
        self.assertTrue(a.meta[3].http_line)

    def test_tuple_reuse_and_direction(self):
        a = Analyzer()
        a.add(1, 0, pkt(seq=10, flags=2))
        a.add(2, .1, pkt(sport=8000, dport=53000, seq=99, ack=11, flags=0x12))
        a.add(3, .2, pkt(seq=11, ack=100))
        a.add(4, .3, pkt(seq=11, flags=0x11))
        a.add(5, .4, pkt(seq=777, flags=2))
        self.assertEqual(a.streams[0].frames, [1, 2, 3, 4])
        self.assertEqual(a.meta[2].direction, '←')
        self.assertEqual(a.meta[5].stream, 1)

    def test_dns_same_id_distinct_servers(self):
        a = Analyzer()
        msg = dict(protocols=['UDP', 'DNS'], dns_id=42, dns_qtype=1, dns_question='a.local')
        for i, peer in enumerate(('1.1.1.1', '8.8.8.8'), 1):
            a.add(i, i, pkt(dst=peer, dport=53, dns_response=False, **msg))
        a.add(3, 2.25, pkt(src='8.8.8.8', sport=53, dport=53000, dns_response=True, **msg))
        a.add(4, 2.5, pkt(src='1.1.1.1', sport=53, dport=53000, dns_response=True, **msg))
        self.assertEqual(a.meta[3].dns_peer, 2)
        self.assertEqual(a.meta[4].dns_peer, 1)
        self.assertEqual(a.meta[2].dns_ms, 250)

    @unittest.skipUnless(sys.platform == 'darwin', '本机 TCP 进程采样为 macOS 验收')
    def test_loopback_socket_ownership(self):
        with socket.socket() as listener, socket.socket() as client:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            client.connect(listener.getsockname())
            server, _ = listener.accept()
            with server:
                endpoints = client.getsockname(), client.getpeername()
                live = snapshot()
                self.assertIn(f'PID {os.getpid()}', live[endpoints])
                self.assertIn(f'PID {os.getpid()}', live[endpoints[::-1]])


if __name__ == '__main__':
    unittest.main()
