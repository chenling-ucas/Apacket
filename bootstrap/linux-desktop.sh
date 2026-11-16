# Sourced by start-posix.sh on Linux.
check_linux_platform() {
    if [ ! -r /etc/os-release ]; then echo "此启动器需要 Ubuntu 或 Debian 图形桌面。" >&2; return 1; fi
    . /etc/os-release
    local release_major="${VERSION_ID%%.*}" libc version minor
    case "$ID" in
        ubuntu) [ "$release_major" -ge 24 ] || { echo "此版本需要 Ubuntu 24.04 或更新版本。" >&2; return 1; } ;;
        debian) [ "$release_major" -ge 12 ] || { echo "此版本需要 Debian 12 或更新版本。" >&2; return 1; } ;;
        *) echo "此自动配置入口支持 Ubuntu 或 Debian 图形桌面。" >&2; return 1 ;;
    esac
    libc="$(getconf GNU_LIBC_VERSION 2>/dev/null)" || { echo "Qt 发行包需要 glibc。" >&2; return 1; }
    version="${libc##* }"
    minor=34
    if [ "$arch" = aarch64 ]; then minor=39; fi
    if ! dpkg --compare-versions "$version" ge "2.$minor"; then
        echo "该体系结构的 Qt 需要 glibc 2.$minor 或以上，当前为 ${version}。" >&2; return 1
    fi
    pcap_package=libpcap0.8t64
    if [ "$ID" = debian ] && [ "$release_major" -eq 12 ]; then pcap_package=libpcap0.8; fi
}
prepare_linux_desktop() {
    local pkg reply
    local missing=() elevate=()
    # Qt can open an X11 window even when every Chinese label is a missing glyph.
    if ! { command -v fc-list >/dev/null && fc-list -q ':lang=zh-cn'; } &&
       [ "$(dpkg-query -W -f='${db:Status-Status}' fonts-noto-cjk 2>/dev/null)" != installed ]; then
        missing+=(fonts-noto-cjk)
    fi
    # Qt's bundled xcb platform plugin still links to the distribution's X11/GL libraries.
    for pkg in "$pcap_package" lsof libgl1 libegl1 libfontconfig1 libdbus-1-3 libxkbcommon-x11-0 \
            libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
            libxcb-render-util0 libxcb-shape0 libxcb-shm0 libxcb-sync1 libxcb-xfixes0 \
            libxcb-xinerama0 libxcb-xkb1 libx11-xcb1 libxrender1 libsm6 libice6; do
        if [ "$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null)" != installed ]; then missing+=("$pkg"); fi
    done
    if [ "${#missing[@]}" -eq 0 ]; then return; fi
    echo "缺少以下系统组件：${missing[*]}"
    if [ "$(id -u)" -ne 0 ]; then
        if [ ! -t 0 ]; then echo "请从桌面终端运行启动器以安装缺少的系统组件。" >&2; return; fi
        read -r -p "允许系统包管理器安装这些组件吗？[Y/n] " reply || reply=n
        case "$reply" in n|N|no|NO) return 0 ;; esac
        if command -v sudo >/dev/null; then elevate=(sudo)
        elif command -v pkexec >/dev/null; then elevate=(pkexec)
        else echo "需要管理员通过 apt 安装上述组件。" >&2; return; fi
    fi
    if ! "${elevate[@]}" /usr/bin/apt-get update || ! "${elevate[@]}" /usr/bin/apt-get install -y --no-install-recommends "${missing[@]}"; then
        echo "系统组件未安装完成；已安装的组件仍可使用，下次启动会重试。" >&2
    fi
}

offer_linux_capture() {
    # Debian's wireshark-common postinst maintains capabilities on dumpcap across upgrades.
    local current_user reply
    local elevate=()
    if "$python" -I -c 'import socket; socket.socket(socket.AF_PACKET, socket.SOCK_RAW).close()' 2>/dev/null; then return 0; fi
    current_user="$(id -un)"
    local helper_privileged=false
    if [ -u /usr/bin/dumpcap ] || { [ -x /usr/sbin/getcap ] && /usr/sbin/getcap /usr/bin/dumpcap 2>/dev/null | grep -q cap_net_raw; }; then
        helper_privileged=true
    fi
    if "$helper_privileged" && [ -x /usr/bin/dumpcap ] && id -nG | tr ' ' '\n' | grep -Fxq wireshark; then return 0; fi
    if "$helper_privileged" && [ -f /usr/bin/dumpcap ] && id -nG "$current_user" | tr ' ' '\n' | grep -Fxq wireshark; then
        echo "当前账号已经加入 wireshark 组。请注销并重新登录以使用实时抓包。"; return 0
    fi
    echo "实时抓包需要系统的 dumpcap。可通过 apt 安装 wireshark-common，允许 wireshark 组抓包，并将当前账号加入该组。"
    read -r -p "现在配置实时抓包吗？[Y/n，输入 n 直接进入离线分析] " reply || return 1
    case "$reply" in n|N|no|NO) return 1 ;; esac
    if command -v sudo >/dev/null; then elevate=(sudo)
    elif command -v pkexec >/dev/null; then elevate=(pkexec)
    else echo "系统没有可用的管理员授权工具。" >&2; return 1; fi
    "${elevate[@]}" /usr/bin/apt-get update || return 1
    printf '%s\n' 'wireshark-common wireshark-common/install-setuid boolean true' | "${elevate[@]}" /usr/bin/debconf-set-selections || return 1
    "${elevate[@]}" /usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get install -y --no-install-recommends wireshark-common || return 1
    "${elevate[@]}" /usr/sbin/dpkg-reconfigure -f noninteractive wireshark-common || return 1
    "${elevate[@]}" /usr/sbin/usermod -a -G wireshark "$current_user" || return 1
    echo "已配置抓包权限。请注销并重新登录以启用 wireshark 用户组。"
}
