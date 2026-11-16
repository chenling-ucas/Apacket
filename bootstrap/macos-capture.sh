# Sourced only when the user's live capture device needs permission.
offer_mac_capture() (
    local pkg work_dir="" mount_dir="" reply
    echo "实时抓包需要读取 macOS 的 BPF 设备。可安装 Wireshark 官方 ChmodBPF，授权当前账号抓包。"
    pkg="/Applications/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg"
    if [ ! -f "$pkg" ]; then
        echo "需要从 wireshark.org 下载约 140 MiB 的安装镜像。只会安装其中的 ChmodBPF 组件。"
    fi
    read -r -p "现在安装吗？[Y/n，输入 n 直接进入离线分析] " reply || return 1
    case "$reply" in n|N|no|NO) return 1 ;; esac
    if [ ! -f "$pkg" ]; then
        work_dir="$(mktemp -d "$state/.chmodbpf.XXXXXXXX")" || return 1
        mount_dir="$work_dir/image"
        trap 'if /usr/bin/hdiutil detach "$mount_dir" >/dev/null 2>&1 || ! /sbin/mount | /usr/bin/grep -Fq " on $mount_dir ("; then rm -rf "$work_dir"; fi' EXIT
        local dmg="$work_dir/Wireshark.dmg"
        download 'https://www.wireshark.org/download/osx/all-versions/Wireshark%204.6.9.dmg' "$dmg" || return 1
        if [ "$(sha256 "$dmg")" != 10bd54ccdc3f40457f6a1f0c517bc93703fcb327c4cd4b93002e7a623dacbf38 ]; then
            echo "Wireshark 镜像校验失败。" >&2; return 1
        fi
        mkdir "$mount_dir" || return 1
        /usr/bin/hdiutil attach -readonly -nobrowse -mountpoint "$mount_dir" "$dmg" >/dev/null || return 1
        pkg="$mount_dir/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg"
    fi
    local signature
    signature="$(LC_ALL=C /usr/sbin/pkgutil --check-signature "$pkg")" || return 1
    if ! /usr/bin/grep -Fq 'Developer ID Installer: Wireshark Foundation (7Z6EMTD2C6)' <<< "$signature"; then
        echo "无法验证 Wireshark Foundation 的安装包签名。" >&2; return 1
    fi
    /usr/bin/sudo /usr/sbin/installer -pkg "$pkg" -target / || return 1
    if [ ! -r /dev/bpf0 ]; then echo "权限已配置。如果仍提示没有抓包权限，请注销并重新登录 macOS。"; fi
)
