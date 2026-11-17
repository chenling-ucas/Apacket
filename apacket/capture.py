"""System capture and portable capture-file I/O."""
from __future__ import annotations

import ctypes as C
from ctypes.util import find_library
from dataclasses import dataclass
import errno
from functools import lru_cache
from itertools import chain
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Iterable, Iterator


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class Frame:
    timestamp: float
    data: bytes
    wirelen: int
    linktype: int


class CaptureError(RuntimeError):
    pass


_MAX_CAPTURE_BYTES = 128 * 1024 * 1024


class _Timeval(C.Structure):
    # Darwin's suseconds_t is a 32-bit integer even on a 64-bit Mac.
    _fields_ = [('sec', C.c_long), ('usec', C.c_int32 if sys.platform == 'darwin' else C.c_long)]


class _Header(C.Structure):
    _fields_ = [('ts', _Timeval), ('caplen', C.c_uint32), ('length', C.c_uint32)]
    if sys.platform == 'darwin':
        _fields_ += [('comment', C.c_char * 256)]


class _Device(C.Structure):
    pass


_DevicePtr = C.POINTER(_Device)
_Device._fields_ = [
    ('next', _DevicePtr), ('name', C.c_char_p), ('description', C.c_char_p),
    ('addresses', C.c_void_p), ('flags', C.c_uint32),
]


class _BpfProgram(C.Structure):
    _fields_ = [('length', C.c_uint), ('instructions', C.c_void_p)]


@lru_cache(maxsize=1)
def _library():
    if os.name == 'nt':
        npcap_dir = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'Npcap'
        name = str(npcap_dir / 'wpcap.dll') if npcap_dir.is_dir() else 'wpcap.dll'
    else:
        name = find_library('pcap')
        if not name:
            raise CaptureError('找不到 libpcap 动态库，请先安装系统抓包库。')
    try:
        lib = C.CDLL(name, use_errno=True)
    except OSError as exc:
        raise CaptureError(f'无法载入抓包库 {name}：{exc}') from exc

    if os.name == 'nt' and hasattr(lib, 'pcap_init'):
        # Python's Windows filesystem encoding is UTF-8. Npcap otherwise
        # interprets device names and file paths in the system ANSI code page.
        lib.pcap_init.argtypes = [C.c_uint, C.c_char_p]
        lib.pcap_init.restype = C.c_int
        error = C.create_string_buffer(256)
        if lib.pcap_init(1, error) < 0:  # PCAP_CHAR_ENC_UTF_8
            raise CaptureError(f'初始化 Npcap 失败：{_message(error.value)}')

    handle, string, integer = C.c_void_p, C.c_char_p, C.c_int
    header_ptr = C.POINTER(_Header)
    signatures = {
        'pcap_findalldevs': (integer, C.POINTER(_DevicePtr), string),
        'pcap_freealldevs': (None, _DevicePtr),
        'pcap_open_live': (handle, string, integer, integer, integer, string),
        'pcap_open_offline': (handle, string, string),
        'pcap_setnonblock': (integer, handle, integer, string),
        'pcap_datalink': (integer, handle),
        'pcap_compile': (integer, handle, C.POINTER(_BpfProgram), string, integer, C.c_uint32),
        'pcap_setfilter': (integer, handle, C.POINTER(_BpfProgram)),
        'pcap_freecode': (None, C.POINTER(_BpfProgram)),
        'pcap_next_ex': (integer, handle, C.POINTER(header_ptr), C.POINTER(handle)),
        'pcap_geterr': (string, handle),
        'pcap_close': (None, handle),
        'pcap_open_dead': (handle, integer, integer),
        'pcap_dump_open': (handle, handle, string),
        'pcap_dump': (None, handle, header_ptr, handle),
        'pcap_dump_flush': (integer, handle),
        'pcap_dump_close': (None, handle),
    }
    for function_name, (result, *arguments) in signatures.items():
        fn = getattr(lib, function_name)
        fn.argtypes, fn.restype = arguments, result
    return lib


def _message(raw: bytes | None) -> str:
    return (raw or b'unknown libpcap error').decode(errors='replace')


def _mac_hardware_names() -> dict[str, str]:
    try:
        output = subprocess.run(
            ['/usr/sbin/networksetup', '-listallhardwareports'],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors='replace',
            env={**os.environ, 'LC_ALL': 'C'}, check=True, timeout=2,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    names = {}
    label = ''
    for line in output.splitlines():
        if line.startswith('Hardware Port:'):
            label = line.partition(':')[2].strip()
        elif line.startswith('Device:') and label:
            name = line.partition(':')[2].strip()
            if name:
                names[name] = label
            label = ''
    return names


def interfaces() -> list[Interface]:
    linux = sys.platform.startswith('linux')
    if linux:
        from .linux_dumpcap import add_local_interfaces
    try:
        lib = _library()
    except CaptureError:
        if linux and (local := add_local_interfaces([])):
            return local
        raise
    hardware = _mac_hardware_names() if sys.platform == 'darwin' else {}
    devices = _DevicePtr()
    error = C.create_string_buffer(256)
    if lib.pcap_findalldevs(C.byref(devices), error) < 0:
        if linux and (local := add_local_interfaces([])):
            return local
        raise CaptureError(f'读取接口列表失败：{_message(error.value)}')
    result = []
    try:
        current = devices
        while current:
            device = current.contents
            if device.name:
                name = os.fsdecode(device.name)
                description = hardware.get(name) or (device.description or b'').decode(errors='replace')
                if not description and device.flags & 0x01:  # PCAP_IF_LOOPBACK
                    description = 'Loopback'
                result.append(Interface(name, description))
            current = device.next
    finally:
        lib.pcap_freealldevs(devices)
    return add_local_interfaces(result) if linux else result


class Capture:
    """The owning thread opens, reads, and closes this capture handle."""

    def __init__(self, handle):
        self._lib = _library()
        self._handle = handle
        self.linktype = self._lib.pcap_datalink(handle)
        self._header = C.POINTER(_Header)()
        self._data = C.c_void_p()

    def read(self) -> Frame | None:
        if not self._handle:
            raise CaptureError('捕获接口已关闭。')
        rc = self._lib.pcap_next_ex(self._handle, C.byref(self._header), C.byref(self._data))
        if rc in (0, -2):  # no live packets ready / end of offline file
            return None
        if rc != 1:
            raise CaptureError(f'读取数据包失败：{_message(self._lib.pcap_geterr(self._handle))}')
        header = self._header.contents
        # libpcap reuses the buffer returned by pcap_next_ex on the next read.
        return Frame(header.ts.sec + header.ts.usec / 1_000_000,
                     C.string_at(self._data, header.caplen), header.length, self.linktype)

    def close(self):
        if self._handle:
            self._lib.pcap_close(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def open_live(device: str, bpf: str = ''):
    linux = sys.platform.startswith('linux')
    if linux:
        from .linux_dumpcap import HELPER, DumpcapCapture
    try:
        lib = _library()
    except CaptureError:
        if linux and HELPER.is_file():
            return DumpcapCapture(device, bpf)
        raise
    error = C.create_string_buffer(256)
    C.set_errno(0)
    handle = lib.pcap_open_live(os.fsencode(device), 262144, 0, 50, error)
    if not handle:
        detail = _message(error.value)
        if linux and (C.get_errno() in (errno.EACCES, errno.EPERM)
                      or 'permission' in detail.lower() or 'not permitted' in detail.lower()):
            return DumpcapCapture(device, bpf)
        raise CaptureError(f'无法打开 {device}：{detail}')
    try:
        if bpf.strip():
            program = _BpfProgram()
            if lib.pcap_compile(handle, C.byref(program), bpf.encode(), 1, 0xffffffff) < 0:
                raise CaptureError(f'捕获过滤器无效：{_message(lib.pcap_geterr(handle))}')
            try:
                if lib.pcap_setfilter(handle, C.byref(program)) < 0:
                    raise CaptureError(f'设置捕获过滤器失败：{_message(lib.pcap_geterr(handle))}')
            finally:
                lib.pcap_freecode(C.byref(program))
        if lib.pcap_setnonblock(handle, 1, error) < 0:
            raise CaptureError(f'设置非阻塞捕获失败：{_message(error.value)}')
        return Capture(handle)
    except BaseException:
        lib.pcap_close(handle)
        raise


def read_file(path: str | os.PathLike) -> Iterator[Frame]:
    """Use the portable reader when a native capture library is unavailable."""
    try:
        lib = _library()
    except CaptureError:
        from .offline_pcap import read
        yield from read(path)
        return
    error = C.create_string_buffer(256)
    handle = lib.pcap_open_offline(os.fsencode(path), error)
    if not handle:
        raise CaptureError(f'无法打开抓包文件：{_message(error.value)}')
    with Capture(handle) as capture:
        while (frame := capture.read()) is not None:
            yield frame


def _records(frames, linktype):
    for frame in frames:
        if frame.linktype != linktype:
            raise CaptureError('传统 pcap 只能保存同一种链路类型。')
        size = len(frame.data)
        if not size <= frame.wirelen <= 0xffffffff or size > _MAX_CAPTURE_BYTES:
            raise CaptureError('捕获长度或原始帧长超出 pcap 支持范围。')
        seconds, usecs = divmod(round(frame.timestamp * 1_000_000), 1_000_000)
        if not 0 <= seconds <= 0xffffffff:
            raise CaptureError('时间戳超出 pcap 支持范围。')
        yield frame, seconds, usecs


def _write_native(lib, path, linktype, records):
    handle = lib.pcap_open_dead(linktype, _MAX_CAPTURE_BYTES)
    if not handle:
        raise CaptureError('无法创建 pcap 输出上下文。')
    try:
        writer = lib.pcap_dump_open(handle, os.fsencode(path))
        if not writer:
            raise CaptureError(f'创建抓包文件失败：{_message(lib.pcap_geterr(handle))}')
        try:
            for frame, seconds, usecs in records:
                header = _Header()
                header.ts.sec, header.ts.usec = seconds, usecs
                header.caplen, header.length = len(frame.data), frame.wirelen
                lib.pcap_dump(writer, C.byref(header), frame.data)
            if lib.pcap_dump_flush(writer) < 0:
                raise CaptureError('写入抓包文件失败，请检查磁盘空间。')
        finally:
            lib.pcap_dump_close(writer)
    finally:
        lib.pcap_close(handle)


def save_file(path: str | os.PathLike, frames: Iterable[Frame]) -> None:
    """Export a single link type to classic pcap, replacing the target on success."""
    frames = iter(frames)
    first = next(frames, None)
    if first is None:
        raise CaptureError('没有可保存的数据包。')
    records = _records(chain((first,), frames), first.linktype)
    target = Path(path)
    with tempfile.NamedTemporaryFile(dir=target.parent, prefix='.apacket-', delete=False) as tmp:
        temporary = Path(tmp.name)
    try:
        try:
            lib = _library()
        except CaptureError:
            from .offline_pcap import write
            write(temporary, first.linktype, records)
        else:
            _write_native(lib, temporary, first.linktype, records)
        os.replace(temporary, target)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
