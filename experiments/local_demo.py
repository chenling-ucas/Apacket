"""Generate three recognisable conversations on the Mac loopback interface."""
from __future__ import annotations

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import secrets
import shutil
import socket
import struct
import subprocess
import threading
import time


LOCALHOST = '127.0.0.1'
BODY = b'PacketScope local HTTP demonstration\n'


def send_echoes(identifier: int, nonce: bytes) -> None:
    """Darwin permits unprivileged ICMP echo datagram sockets."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as echo:
        for seq in (1, 2, 3):
            payload = struct.pack('!BBHHH', 8, 0, 0, identifier, seq) + nonce + b'PacketScope!'
            words = struct.unpack(f'!{len(payload) // 2}H', payload)
            value = sum(words)
            while value >> 16:
                value = (value & 0xffff) + (value >> 16)
            checksum = struct.pack('!H', (~value) & 0xffff)
            echo.sendto(payload[:2] + checksum + payload[4:], (LOCALHOST, 0))
            time.sleep(.09)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def do_GET(self):
        if self.path not in ('/demo.txt', '/curl'):
            self.send_error(404)
            return
        self.send_response_only(200)
        self.send_header('Content-Length', str(len(BODY)))
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(BODY[:4])
        self.wfile.flush()
        if self.path == '/curl':
            # Hold both sockets while attribution is sampled.
            self.server.curl_ready.set()
            self.server.release_curl.wait(10)
        self.wfile.write(BODY[4:])
        self.close_connection = True

    def log_message(self, *_):
        pass


@contextmanager
def demo_server():
    with ThreadingHTTPServer((LOCALHOST, 0), Handler) as server:
        server.curl_ready = threading.Event()
        server.release_curl = threading.Event()
        runner = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        runner.start()
        try:
            yield server
        finally:
            server.release_curl.set()
            server.shutdown()
            runner.join()


def split_request(port):
    with socket.create_connection((LOCALHOST, port), timeout=5) as stream:
        stream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        stream.sendall(b'GET /de')
        time.sleep(.18)
        stream.sendall(b'mo.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
        response = http.client.HTTPResponse(stream)
        response.begin()
        if response.status != 200 or response.read() != BODY:
            raise RuntimeError('拆分 HTTP 请求响应异常')


def curl_request(server, sample_owners):
    """Run a distinct client, invoking the sampler after the response starts."""
    curl = shutil.which('curl')
    if not curl:
        raise RuntimeError('本机缺少 curl')
    command = [curl, '-q', '--noproxy', '*', '--silent', '--show-error', '--fail',
               '--http1.1', '--max-time', '12', f'http://{LOCALHOST}:{server.server_port}/curl']
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        try:
            if not server.curl_ready.wait(5):
                raise RuntimeError('curl 未在 5 秒内进入传输')
            outcome = sample_owners(proc.pid)
        finally:
            server.release_curl.set()
        body, errors = proc.communicate(timeout=7)
        if proc.returncode or body != BODY:
            raise RuntimeError('curl 响应异常：' + errors.decode(errors='replace'))
        return outcome


def main():
    with demo_server() as server:
        print(f'回环演示：127.0.0.1:{server.server_port}，Python 服务 PID {os.getpid()}', flush=True)
        send_echoes(secrets.randbelow(65535) + 1, secrets.token_bytes(4))
        split_request(server.server_port)
        print('GET /demo.txt 跨两次发送，已收到 HTTP 200。', flush=True)
        def hold(pid):
            print(f'独立 curl 客户端 PID {pid}，连接保持 3 秒用于进程采样。', flush=True)
            time.sleep(3)
        curl_request(server, hold)
    print('完成，可停止抓包并查看 ICMP、HTTP 和 TCP 流。')


if __name__ == '__main__':
    main()
