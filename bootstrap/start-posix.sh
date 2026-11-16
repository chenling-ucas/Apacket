#!/bin/bash
# A read-only checkout is enough. The runtime and locked wheels live in the current user's directory.
set -eu
umask 077
script_dir="$(cd "$(dirname "$0")" && pwd -P)"
project_dir="$(cd "$script_dir/.." && pwd -P)"
system_name="$(uname -s)"
machine="$(uname -m)"
case "$machine" in
    arm64|aarch64) arch=aarch64 ;;
    x86_64|amd64) arch=x86_64 ;;
    *) echo "此版本需要 64 位 Intel/AMD 或 ARM 处理器。" >&2; exit 1 ;;
esac
case "$system_name" in
    Darwin)
        major="$(/usr/bin/sw_vers -productVersion | cut -d. -f1)"
        if [ "$major" -lt 13 ]; then echo "此版本的界面需要 macOS 13 或更新版本。" >&2; exit 1; fi
        default_state="$HOME/Library/Application Support/PacketScope"
        target="$arch-apple-darwin"
        ;;
    Linux)
        default_state="${XDG_DATA_HOME:-$HOME/.local/share}/PacketScope"
        target="$arch-unknown-linux-gnu"
        source "$script_dir/linux-desktop.sh"
        check_linux_platform
        ;;
    *) echo "此启动入口适用于 macOS 和 Linux。" >&2; exit 1 ;;
esac
state="${PACKETSCOPE_DATA_DIR:-$default_state}"
mkdir -p "$state"
state="$(cd "$state" && pwd -P)"
requirements="$project_dir/requirements.txt"

sha256() {
    if [ "$system_name" = Darwin ]; then /usr/bin/shasum -a 256 "$1" | cut -d' ' -f1
    else sha256sum "$1" | cut -d' ' -f1; fi
}
download() {
    if command -v curl >/dev/null; then
        curl --fail --location --retry 2 --connect-timeout 15 --max-time 600 --proto '=https' --proto-redir '=https' --output "$2" "$1"
    else
        wget --https-only --timeout=45 --tries=3 -O "$2" "$1"
    fi
}
venv_dir="$state/venv-$target-$(sha256 "$requirements" | cut -c1-12)"
ready() {
    [ -x "$1" ] && "$1" -I -c '
import importlib.metadata as meta, re, sys
from PySide6 import QtWidgets
assert (3, 10) <= sys.version_info[:2] < (3, 15)
with open(sys.argv[1], encoding="utf-8") as req:
    pins = re.findall(r"(?m)^([\w.-]+)==([^\s\\]+)", req.read())
assert pins and all(meta.version(name) == version for name, version in pins)
' "$requirements" >/dev/null 2>&1
}
can_create_venv() {
    [ -x "$1" ] && "$1" -I -c 'import ensurepip, sys, sysconfig, venv
sys.exit(not ((3,10) <= sys.version_info[:2] < (3,15)) or bool(sysconfig.get_config_var("Py_GIL_DISABLED")))' >/dev/null 2>&1
}
create_system_venv() {
    local py resolved
    for py in python3.13 python3.14 python3.12 python3.11 python3.10 python3; do
        resolved="$(command -v "$py")" || continue
        # Invoking Apple's developer-tool stub on a new Mac would open an unrelated installer.
        if [ "$system_name" = Darwin ] && [ "$resolved" = /usr/bin/python3 ]; then continue; fi
        can_create_venv "$resolved" || continue
        if "$resolved" -I -m venv --clear "$venv_dir" && "$venv_dir/bin/python" -I -m pip --version >/dev/null; then return 0; fi
    done
    return 1
}
create_portable_venv() {
    local release=20261110 version=3.13.18 digest runtime archive
    case "$target" in
        aarch64-apple-darwin) digest=7a2384641584ab9984221fcb0fc9265df465922af71be71410529e2a9c3f0540 ;;
        x86_64-apple-darwin) digest=d27d59a722db9f69926eb6d9564071247221f45a04da920ea7f3001c97e32f9b ;;
        aarch64-unknown-linux-gnu) digest=55c00325f7c1fddf325dfc621aabdfbbac4dc54adda224af88ec411dc12db239 ;;
        x86_64-unknown-linux-gnu) digest=f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb ;;
    esac
    runtime="$state/cpython-$version-$release-$target"
    if [ ! -x "$runtime/bin/python3" ]; then
        archive="cpython-$version%2B$release-$target-install_only_stripped.tar.gz"
        echo "正在为 PacketScope 下载 Python ${version}…"
        download "https://github.com/astral-sh/python-build-standalone/releases/download/$release/$archive" "$work/python.tar.gz"
        if [ "$(sha256 "$work/python.tar.gz")" != "$digest" ]; then echo "Python 下载校验失败，请重新启动。" >&2; return 1; fi
        mkdir "$work/python"
        tar -xzf "$work/python.tar.gz" -C "$work/python" --strip-components=1
        "$work/python/bin/python3" -I -c 'import ssl, sqlite3, venv'
        mv "$work/python" "$runtime"
    fi
    "$runtime/bin/python3" -I -m venv --clear "$venv_dir"
}
prepare_runtime() {
    ready "$venv_dir/bin/python" && return 0
    work="$(mktemp -d "$state/.setup.XXXXXXXX")"
    trap 'setup_status=$?; rm -rf "$work"; exit "$setup_status"' EXIT
    if ! can_create_venv "$venv_dir/bin/python" || ! "$venv_dir/bin/python" -I -m pip --version >/dev/null 2>&1; then
        create_system_venv || create_portable_venv
    fi
    echo "正在安装 PacketScope 的界面依赖…"
    "$venv_dir/bin/python" -I -m pip --isolated install --force-reinstall --disable-pip-version-check --only-binary=:all: --index-url https://pypi.org/simple -r "$requirements"
    if ! ready "$venv_dir/bin/python"; then "$venv_dir/bin/python" -I -c 'from PySide6 import QtWidgets' || true; echo "无法载入已安装的 Qt 界面，请检查上方的安装信息。" >&2; return 1; fi
}

if [ "${1:-}" = --prepare-runtime ]; then prepare_runtime; exit; fi
if [ "$system_name" = Linux ]; then prepare_linux_desktop; fi
python="$project_dir/.venv/bin/python"
if ! ready "$python"; then
    python="$venv_dir/bin/python"
    if ! ready "$python"; then
        # Use an OS lock which is released even if setup is interrupted.
        if [ "$system_name" = Darwin ]; then
            /usr/bin/lockf -k -t 600 "$state/setup.lock" /bin/bash "$script_dir/start-posix.sh" --prepare-runtime
        else
            flock -w 600 "$state/setup.lock" /bin/bash "$script_dir/start-posix.sh" --prepare-runtime
        fi
        if ! ready "$python"; then echo "运行环境未准备完成。解决上方的错误后，重新打开启动器即可重试。" >&2; exit 1; fi
    fi
fi
cd "$project_dir"
if [ "${1:-}" = --check ]; then
    QT_QPA_PLATFORM=offscreen "$python" -c '
import platform, sys
from PySide6 import QtWidgets, __version__
from packetscope import capture
from packetscope.gui import Window
app = QtWidgets.QApplication([])
print(f"Python {platform.python_version()} / Qt for Python {__version__} / Qt 平台 {app.platformName()}")
print(f"Python 解释器：{sys.executable}")
try:
    capture._library()
except (OSError, RuntimeError) as exc:
    print(f"实时捕获库不可用：{exc}")
else:
    print("已载入系统抓包库。")
'
    exit
fi
if [ "$system_name" = Darwin ] && [ "$#" -eq 0 ] && [ -t 0 ] && [ ! -r /dev/bpf0 ]; then
    source "$script_dir/macos-capture.sh"
    offer_mac_capture || echo "本次继续打开 PacketScope。可打开已有的抓包文件。" >&2
fi
if [ "$system_name" = Linux ] && [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}${QT_QPA_PLATFORM:-}" ]; then
    echo "请在图形桌面中启动 PacketScope。终端环境可运行 bash Start-PacketScope-Linux.sh --check。" >&2
    exit 1
fi
if [ "$system_name" = Linux ] && [ "$#" -eq 0 ] && [ -t 0 ]; then
    offer_linux_capture || echo "本次继续打开 PacketScope。可打开已有的抓包文件。" >&2
fi
exec "$python" -m packetscope "$@"
