"""在 lo0 上生成三组可识别的本机流量，供实时演示。"""
import http.client
import socket
import subprocess
import sys
import tempfile
import threading
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    print('先启动抓包，选择 lo0。此脚本只使用 127.0.0.1。', flush=True)
    subprocess.run(['/sbin/ping', '-c', '3', '127.0.0.1'], check=True)
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, 'demo.txt').write_text('PacketScope local HTTP demonstration\n')
        handler = partial(SimpleHTTPRequestHandler, directory=directory)
        with ThreadingHTTPServer(('127.0.0.1', 0), handler) as server:
            port = server.server_port
            threading.Thread(target=server.serve_forever, daemon=True).start()
            # Keep the socket open long enough for a live process snapshot.
            with socket.create_connection(('127.0.0.1', port), timeout=8) as stream:
                stream.sendall(b'GET /de')
                time.sleep(1.8)
                stream.sendall(b'mo.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
                response = http.client.HTTPResponse(stream)
                response.begin()
                print('分两次写入 GET 请求，回复', response.status, response.read().decode().strip())
            server.shutdown()
    print('可以停止抓包，按 ICMP、HTTP 或 TCP 流查看。')


if __name__ == '__main__':
    main()
