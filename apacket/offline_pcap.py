"""Read common PCAP/PCAPNG files without a capture driver; write classic PCAP."""
import struct

from .capture import CaptureError, Frame, _MAX_CAPTURE_BYTES


_MAGIC = {
    bytes.fromhex('d4c3b2a1'): ('<', 10**6), bytes.fromhex('a1b2c3d4'): ('>', 10**6),
    bytes.fromhex('4d3cb2a1'): ('<', 10**9), bytes.fromhex('a1b23c4d'): ('>', 10**9),
}
_SECTION = bytes.fromhex('0a0d0d0a')
_BYTE_ORDER = {bytes.fromhex('4d3c2b1a'): '<', bytes.fromhex('1a2b3c4d'): '>'}


def _exact(file, count):
    data = file.read(count)
    if len(data) != count:
        raise CaptureError('抓包文件在记录结束前截断。')
    return data


def _lengths(captured, original, snaplen):
    if captured > original or captured > _MAX_CAPTURE_BYTES or (snaplen and captured > snaplen):
        raise CaptureError('抓包记录中的捕获长度超出限制或超过原始帧长。')


def _linktype(value):
    # LINKTYPE_RAW in both file formats is 101. The supported operating
    # systems use 12 (DLT_RAW) at the native capture API boundary.
    return 12 if value == 101 else value


def read(path):
    with open(path, 'rb') as file:
        magic = _exact(file, 4)
        if magic == _SECTION:
            yield from _pcapng(file, magic)
        elif magic in _MAGIC:
            yield from _pcap(file, *_MAGIC[magic])
        else:
            raise CaptureError('未识别的抓包格式。离线模式支持经典 PCAP 和常见的 PCAPNG 文件。')


def read_classic_stream(file):
    """Read the classic PCAP stream written to stdout by the system dumpcap."""
    magic = _exact(file, 4)
    if magic not in _MAGIC:
        raise CaptureError('dumpcap 返回了无法识别的数据。')
    yield from _pcap(file, *_MAGIC[magic])


def _pcap(file, order, units):
    major, minor, _, _, snaplen, network = struct.unpack(order + 'HHIIII', _exact(file, 20))
    if (major, minor) != (2, 4) or not snaplen:
        raise CaptureError('不支持的 PCAP 版本或无效的快照长度。')
    linktype = _linktype(network & 0xffff)
    header = struct.Struct(order + 'IIII')
    while raw := file.read(header.size):
        if len(raw) != header.size:
            raise CaptureError('PCAP 包头被截断。')
        seconds, fraction, captured, original = header.unpack(raw)
        if fraction >= units:
            raise CaptureError('PCAP 时间戳的小数部分超出范围。')
        _lengths(captured, original, snaplen)
        yield Frame(seconds + fraction / units, _exact(file, captured), original, linktype)


def _options(data, order):
    pos = 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise CaptureError('PCAPNG 选项头被截断。')
        code, size = struct.unpack_from(order + 'HH', data, pos)
        pos += 4
        end = pos + ((size + 3) & ~3)
        if end > len(data):
            raise CaptureError('PCAPNG 选项数据被截断。')
        if code == 0:
            if size or pos != len(data):
                raise CaptureError('PCAPNG 选项结束标记无效。')
            return
        yield code, data[pos:pos + size]
        pos = end


def _interface(body, order):
    if len(body) < 8:
        raise CaptureError('PCAPNG 接口描述被截断。')
    link, _, snaplen = struct.unpack_from(order + 'HHI', body)
    units, offset = 10**6, 0
    for code, value in _options(body[8:], order):
        if code == 9:  # if_tsresol
            if len(value) != 1:
                raise CaptureError('PCAPNG 时间分辨率长度无效。')
            n = value[0]
            units = 2 ** (n & 127) if n & 128 else 10 ** n
        elif code == 14:  # if_tsoffset (signed seconds)
            if len(value) != 8:
                raise CaptureError('PCAPNG 时间偏移长度无效。')
            offset, = struct.unpack(order + 'q', value)
    return _linktype(link), snaplen, units, offset


def _packet(body, order, interfaces):
    if len(body) < 20:
        raise CaptureError('PCAPNG 增强包头被截断。')
    index, high, low, captured, original = struct.unpack_from(order + '5I', body)
    if index >= len(interfaces):
        raise CaptureError('PCAPNG 包引用了不存在的接口。')
    link, snaplen, units, offset = interfaces[index]
    _lengths(captured, original, snaplen)
    end = 20 + ((captured + 3) & ~3)
    if end > len(body):
        raise CaptureError('PCAPNG 帧数据被截断。')
    for _ in _options(body[end:], order):
        pass  # Validate optional packet metadata, which Frame does not expose.
    timestamp = offset + ((high << 32) | low) / units
    return Frame(timestamp, bytes(body[20:20 + captured]), original, link)


def _pcapng(file, kind_bytes):
    interfaces = []
    expected_link = section_end = None
    order = '<'
    while kind_bytes:
        if len(kind_bytes) != 4:
            raise CaptureError('PCAPNG 块头被截断。')
        start = file.tell() - 4
        raw_length = _exact(file, 4)
        section = kind_bytes == _SECTION
        if section:
            if section_end is not None and start != section_end:
                raise CaptureError('PCAPNG 区段长度与文件不符。')
            order = _BYTE_ORDER.get(_exact(file, 4))
            if order is None:
                raise CaptureError('无效的 PCAPNG 字节序。')
        length, = struct.unpack(order + 'I', raw_length)
        if (length < (28 if section else 12) or length % 4
                or length > _MAX_CAPTURE_BYTES + 1024 * 1024):
            raise CaptureError('PCAPNG 块长度无效或超过支持范围。')
        if not section and section_end is not None and start + length > section_end:
            raise CaptureError('PCAPNG 块超出区段边界。')
        body = memoryview(_exact(file, length - (16 if section else 12)))
        if _exact(file, 4) != raw_length:
            raise CaptureError('PCAPNG 块首尾长度不一致。')
        kind, = struct.unpack(order + 'I', kind_bytes)
        if section:
            major, minor, extent = struct.unpack_from(order + 'HHq', body)
            if (major, minor) != (1, 0) or extent < -1:
                raise CaptureError('不支持的 PCAPNG 区段版本或长度。')
            section_end = None if extent == -1 else start + length + extent
            interfaces.clear()
        elif kind == 1:
            if len(interfaces) == 65536:
                raise CaptureError('PCAPNG 区段接口数超过支持范围。')
            interface = _interface(body, order)
            if expected_link is not None and interface[0] != expected_link:
                raise CaptureError('暂不支持混合链路类型的 PCAPNG 文件。')
            expected_link = interface[0]
            interfaces.append(interface)
        elif kind == 6:
            yield _packet(body, order, interfaces)
        elif kind not in (4, 5, 10, 0xBAD, 0x40000BAD):
            # In particular, do not silently drop Simple or obsolete Packet Blocks.
            raise CaptureError(f'离线模式不支持 PCAPNG 块类型 0x{kind:X}，可用 Wireshark 转为经典 PCAP。')
        kind_bytes = file.read(4)
    if section_end is not None and file.tell() != section_end:
        raise CaptureError('PCAPNG 区段在预期长度前截断。')


def write(path, linktype, records):
    if not 0 <= linktype <= 0xffff:
        raise CaptureError('链路类型超出 PCAP 支持范围。')
    network = 101 if linktype == 12 else linktype
    with open(path, 'wb') as file:
        file.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, _MAX_CAPTURE_BYTES, network))
        for frame, seconds, usecs in records:
            file.write(struct.pack('<IIII', seconds, usecs, len(frame.data), frame.wirelen))
            file.write(frame.data)
