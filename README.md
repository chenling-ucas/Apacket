# Apacket

带图形界面的网络嗅探器。选择一个网络接口即可实时抓包，点击协议字段可定位原始字节，双击 TCP 帧可查看整条连接的时序。实时捕获时，还能按本机进程查看 TCP 流。

## 启动

在 GitHub 上选择 **Code → Download ZIP**，完整解压。首次运行需要联网，启动器会在当前用户目录配置 Python 和 Qt。

| 平台 | 在解压目录启动 |
| --- | --- |
| Windows x64 / ARM64 | 双击 `Start-Apacket.cmd` |
| macOS | 双击 `启动 Apacket.command` |
| Ubuntu / Debian 图形桌面 | 在终端运行 `bash ./Start-Apacket-Linux.sh` |

实时抓包需要接口访问权限，Windows 还需要 Npcap。启动器会提示如何配置。Windows 下载 Python 和 Qt 时依次尝试清华、阿里云和官方源。给启动器加上 `--check` 可查看实际使用的 Python 路径与抓包库状态。

## 读一条连接

1. 点击“打开文件”，选择[回环示例](examples/loopback-demo.pcap)，在显示过滤框输入 `tcp.stream == 0` 并按回车。
2. 双击第 7 帧查看握手，再看第 11 和 13 帧。两段载荷合起来是 `GET /demo.txt HTTP/1.1`。
3. 要看哪个程序发起了连接，选择网卡、点击“开始抓包”，让目标程序发起 TCP 下载，再点“按进程查看”。进程信息来自当时的系统连接表，普通 PCAP 文件中没有 PID。

[源码](apacket)包含捕获、解码、会话分析和图形界面。[实验脚本](experiments)生成本机回环流量；用启动器自检打印的 Python 运行 `-m unittest discover -s tests -v` 可执行[回归测试](tests)。项目使用 [MIT 许可证](LICENSE)。
