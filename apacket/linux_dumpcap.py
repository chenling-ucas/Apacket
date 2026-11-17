"""Use the distro's privilege-separated dumpcap for local Linux interfaces."""
from pathlib import Path
import queue
import socket
import subprocess
import threading

from .capture import CaptureError, Interface
from .offline_pcap import read_classic_stream


HELPER = Path('/usr/bin/dumpcap')
_PERMISSION_HELP = '请在发行版中授权当前用户运行 dumpcap；新加入 wireshark 组后需注销并重新登录。'


def _local_names():
    # dumpcap also accepts filenames, stdin and remote capture endpoints for -i.
    # Only actual kernel network interfaces and Linux's aggregate interface qualify.
    names = {name for _, name in socket.if_nameindex()
             if not name.startswith('-') and '/' not in name and not name.lower().startswith('tcp@')
             and not name.isdecimal()}
    return names | {'any'}


def add_local_interfaces(existing):
    if HELPER.is_file():
        seen = {device.name for device in existing}
        for name in sorted(_local_names() - seen):
            label = {'lo': 'Loopback', 'any': '所有本机接口'}.get(name, '')
            existing.append(Interface(name, label))
    return existing


class DumpcapCapture:
    def __init__(self, device, bpf):
        if device not in _local_names():
            raise CaptureError('dumpcap 只接受本机网卡或 any。')
        args = [str(HELPER), '-q', '-p', '-P', '-s', '262144', '-i', device]
        if bpf.strip():
            args.extend(['-f', bpf])
        args.extend(['-w', '-'])
        try:
            self._child = subprocess.Popen(
                args, cwd='/', stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'},
            )
        except FileNotFoundError as exc:
            raise CaptureError('普通用户实时抓包需要系统的 /usr/bin/dumpcap。') from exc
        except PermissionError as exc:
            raise CaptureError(_PERMISSION_HELP) from exc

        # The reader can block on an idle interface. The capture worker and the
        # Stop button can still make progress, and buffered packet data is bounded.
        self._frames = queue.Queue(maxsize=32)
        self._stopping = threading.Event()
        self._ended = threading.Event()
        self._detail = bytearray()
        self._read_error = ''
        self._readers = [threading.Thread(target=target, daemon=True)
                         for target in (self._collect_errors, self._receive)]
        try:
            for thread in self._readers:
                thread.start()
        except BaseException:
            self.close()
            raise

    def _collect_errors(self):
        while chunk := self._child.stderr.read(2048):
            self._detail.extend(chunk)
            del self._detail[:-4096]

    def _receive(self):
        try:
            for frame in read_classic_stream(self._child.stdout):
                while not self._stopping.is_set():
                    try:
                        self._frames.put(frame, timeout=0.05)
                        break
                    except queue.Full:
                        continue
                else:
                    return
        except (OSError, CaptureError) as exc:
            self._read_error = str(exc)
        finally:
            self._ended.set()

    def read(self):
        if self._stopping.is_set():
            raise CaptureError('捕获接口已关闭。')
        ended = self._ended.is_set()
        try:
            return self._frames.get_nowait()
        except queue.Empty:
            if not ended:
                return None
        self.close()
        detail = self._detail.decode(errors='replace').strip() or self._read_error
        if 'permission' in detail.lower() or 'not permitted' in detail.lower():
            detail += '\n' + _PERMISSION_HELP
        raise CaptureError('系统 dumpcap 已停止。' + detail)

    def close(self):
        if self._stopping.is_set():
            return
        self._stopping.set()
        if self._child.poll() is None:
            self._child.terminate()
        try:
            self._child.wait(timeout=0.7)
        except subprocess.TimeoutExpired:
            self._child.kill()
            self._child.wait()
        for thread in self._readers:
            if thread.ident is not None:
                thread.join()
        self._child.stdout.close()
        self._child.stderr.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
