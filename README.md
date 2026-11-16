# PacketScope

实验 1A 的桌面网络嗅探器。Python 用 ctypes 调用系统 libpcap，协议解析和连接追踪代码使用标准库，桌面界面使用 PySide6。开发和实时验收平台为 macOS。

## 在 Mac 上打开

双击本目录的 **启动 PacketScope.command**。第一次在新电脑上使用需要有 Python 3.10–3.13，启动脚本会建立本地虚拟环境并安装界面依赖。也可以在项目目录运行：

```sh
.venv/bin/python -m packetscope
.venv/bin/python -m packetscope examples/loopback-demo.pcap
```

- **离线分析**：点击“打开文件”，选择自带的 `examples/loopback-demo.pcap` 或自己的 PCAP/PCAPNG。点选一个包，展开“协议详情”，点击具体字段即可在 HEX 视图定位其字节。双击 DNS 配对帧可跳转。
- **实时捕获**：选择 `lo0` 抓本机通信，或选择 Wi-Fi 接口查看经过无线网卡的流量。点击“开始抓包”，完成后点击“停止”。“另存 PCAP”保存全部捕获帧，显示过滤器不改变文件内容。
- **演示流量**：在界面上选择 `lo0` 开始，全程只在本机收发示例请求。另开终端，在项目目录执行 `.venv/bin/python experiments/local_demo.py`。脚本产生三对 ICMP、一条分两段发送的 HTTP 请求，以及一条由 curl 发起的独立连接。选择“按进程查看”可以找到记录到的 PID，双击其中的流查看时序。
- **TCP 时序**：双击 TCP 包或点“追踪 TCP 流”。时间相对于该流的首帧，方向根据两端的地址和端口判断。报文列表列出该流各帧，“时序图”可显示前 400 帧。

## 过滤

捕获前的输入框使用 libpcap 的 BPF 语法，例如 `tcp port 8000` 或 `icmp`。界面上第二个输入框用于过滤已捕获的帧，输入后按回车生效。支持括号、`and`、`or`、`not`，以及以下常用写法：

| 想看什么 | 显示过滤器 |
| --- | --- |
| 局域网设备发现 / 普通 DNS / HTTP 请求与响应 | `mdns` / `dns` / `http` |
| 本机 ping | `ip.addr == 127.0.0.1 and icmp` |
| 经过某个端口的 TCP 或 UDP 流量 | `tcp.port == 443 or udp.port == 443` |
| 单条 TCP 流或指定帧 | `tcp.stream == 0` / `frame.number == 3` |
| 来自 curl 的 TCP 流 | `process contains curl` |
| 摘要中的文字 | `info contains "GET /demo"` |

## 实现与验证

- `packetscope/capture.py` 负责枚举接口、BPF、实时捕获和抓包文件读写。离线支持系统 libpcap 可读取的文件；经典 PCAP 仅容纳单一链路类型，以微秒精度导出。
- `packetscope/decode.py` 逐层解析链路、网络、传输与部分应用层，记录各字段在帧中的偏移和长度。支持以太网、本机回环、IPv4/IPv6、TCP/UDP、ICMP/ICMPv6、ARP、DNS/mDNS、明文 HTTP/1.x 和部分 TLS 字段。
- `packetscope/analysis.py` 追踪双向 TCP 连接、关联 DNS 请求与应答，并在每条 TCP 流的每个方向重组第一条 HTTP/1.x 起始行（上限 8192 字节）。DNS 耗时以捕获时间戳计算。
- `packetscope/processes.py` 在实时捕获时采样本机可见的 TCP 套接字。未在采样时出现的短连接可能无法关联；普通 PCAP 不包含此程序采集的进程快照。TLS 解析展示可识别的明文记录与握手字段，不解密应用数据。
- `packetscope/gui.py`、`views.py` 管理数据包列表、字段与字节联动、进程列表和时序图。`experiments/` 下放本机流量演示与验收脚本，`tests/` 下放回归测试。

在项目目录运行：

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python experiments/acceptance.py --live
```

如需和本次课程使用的 192 帧参考文件对照，可执行 `.venv/bin/python experiments/acceptance.py --sample "/路径/1.pcapng"`。该私有文件不随项目分发；随项目附带的示例只含回环测试流量。
