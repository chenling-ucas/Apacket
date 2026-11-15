"""Check the app's own decoder, display filters, reassembly and capture against real traffic."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from packetscope.capture import open_live, read_file, save_file
from packetscope.processes import snapshot
from packetscope.session import Session, display_predicate
from experiments.local_demo import LOCALHOST, curl_request, demo_server, send_echoes, split_request


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def load_frames(frames):
    session = Session()
    for frame in frames:
        session.append(frame)
    return session


def check_sample(path: Path) -> dict:
    session = load_frames(read_file(path))
    check(len(session.records) == 192, '参考样本应有 192 帧')
    mdns = display_predicate('mdns')
    count = sum(mdns(session, r) for r in session.records)
    check(count == 79, f'mDNS 帧数不一致：{count}')
    meta = session.analysis.meta
    handshake = (39, 44, 47)
    stream = meta[39].stream
    check(stream is not None and all(meta[n].stream == stream for n in handshake), '握手未归入同一流')
    flags = [session.records[n - 1].packet.flags for n in handshake]
    check(flags == [2, 18, 16], f'握手标志不一致：{flags}')
    dns = []
    for request, response, expected_ms in ((41, 57, 13.985), (42, 46, 8.275)):
        check(meta[request].dns_peer == response and meta[response].dns_peer == request,
              f'DNS 第 {request} 和 {response} 帧未相互配对')
        measured = meta[response].dns_ms
        check(measured is not None and abs(measured - expected_ms) < .002, 'DNS 耗时不一致')
        dns.append({'request': request, 'response': response, 'ms': round(measured, 3)})
    return {'frames': len(session.records), 'mdns': count, 'tcp_stream': stream,
            'handshake_frames': list(handshake), 'flags': flags, 'dns_pairs': dns}


def check_live(save_demo: Path | None) -> dict:
    identifier = secrets.randbelow(65535) + 1
    nonce = secrets.token_bytes(4)
    with demo_server() as server:
        port = server.server_port
        bpf = (f'src host {LOCALHOST} and dst host {LOCALHOST} and '
               f'((icmp and icmp[4:2] = {identifier} and icmp[8:4] = 0x{nonce.hex()}) '
               f'or (tcp port {port}))')
        with open_live('lo0', bpf) as capture:
            send_echoes(identifier, nonce)
            split_request(port)
            curl_pid, observed = curl_request(server, lambda pid: (pid, snapshot()))
            # Nonblocking libpcap batches delivery; allow the last FIN/ACK to arrive.
            frames = []
            deadline = time.monotonic() + .4
            while time.monotonic() < deadline:
                frame = capture.read()
                if frame is None:
                    time.sleep(.005)
                else:
                    frames.append(frame)
    session = load_frames(frames)
    check(all(r.packet.src == LOCALHOST and r.packet.dst == LOCALHOST for r in session.records),
          '演示数据含有回环以外的地址')
    echoes = []
    for rec in session.records:
        for layer in rec.packet.layers:
            if layer.name == 'ICMP':
                fields = {field.name: field.value for field in layer.fields}
                echoes.append((int(fields['Type'].split()[0]), int(fields['Sequence'])))
    expected = [(kind, seq) for seq in (1, 2, 3) for kind in (8, 0)]
    check(sorted(echoes) == sorted(expected), f'期望三对 ICMP，实际 {echoes}')

    analysis = session.analysis
    split_line = 'GET /demo.txt HTTP/1.1'
    linked = [r for r in session.records if analysis.meta[r.number].http_line == split_line]
    check(len(linked) >= 2 and all(not r.packet.http_line for r in linked),
          '未从至少两个单独不可识别的 TCP 段恢复请求行')
    split_stream = analysis.streams[analysis.meta[linked[0].number].stream]
    check(any(line.startswith('HTTP/1.1 200') for _, line in split_stream.http_events),
          '未识别拆分请求的服务器响应')
    curl_stream = next((s for s in analysis.streams if any(
        line == 'GET /curl HTTP/1.1' for _, line in s.http_events)), None)
    check(curl_stream is not None, '未发现独立 curl 请求')
    client = observed.get((curl_stream.left, curl_stream.right), '')
    service = observed.get((curl_stream.right, curl_stream.left), '')
    check(client.endswith(f'(PID {curl_pid})'), f'curl 进程归属不匹配：{client!r}')
    check(service.endswith(f'(PID {os.getpid()})'), f'Python 服务进程归属不匹配：{service!r}')
    session.owners[curl_stream.id] = {curl_stream.left: client, curl_stream.right: service}
    filter_curl = display_predicate('process contains curl')
    check([r.number for r in session.records if filter_curl(session, r)] == curl_stream.frames,
          '按进程过滤的结果与 curl 连接不符')
    if save_demo is not None:
        save_demo.parent.mkdir(parents=True, exist_ok=True)
        save_file(save_demo, frames)
        check(list(read_file(save_demo)) == frames, '保存并重新读取的帧出现差异')
    return {'frames': len(frames), 'icmp_type_sequence': echoes, 'tcp_streams': len(analysis.streams),
            'http_reassembled': split_line, 'http_contributing_frames': [r.number for r in linked],
            'curl_tcp_stream': curl_stream.id, 'client': client, 'server': service,
            'process_filter_frames': len(curl_stream.frames), 'saved': str(save_demo) if save_demo else None}


def main():
    parser = argparse.ArgumentParser(description='PacketScope 实验 1A 验收（实时部分使用 macOS lo0）')
    parser.add_argument('--sample', type=Path, help='此前分析的 192 帧参考样本 1.pcapng')
    parser.add_argument('--live', action='store_true', help='生成并捕获本机 ICMP、HTTP 与 curl 流量')
    parser.add_argument('--save-demo', type=Path, help='将本次生成的回环演示流量导出为经典 pcap，隐含 --live')
    args = parser.parse_args()
    if not (args.sample or args.live or args.save_demo):
        parser.error('请提供 --sample、--live 或 --save-demo')
    if args.save_demo and args.sample and args.save_demo.resolve() == args.sample.resolve():
        parser.error('演示输出不能覆盖输入样本')
    result = {}
    if args.sample:
        result['sample'] = check_sample(args.sample)
    if args.live or args.save_demo:
        result['live'] = check_live(args.save_demo)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
