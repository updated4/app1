# Terminal Packet Sniffer - Python Network Analysis Tool

![Python Version](https://img.shields.io/badge/Python-3.6%2B-blue)
![Scapy Version](https://img.shields.io/badge/Scapy-2.4.5%2B-orange)
![License](https://img.shields.io/badge/License-MIT-green)

**Terminal Packet Sniffer** 是一个功能强大的命令行网络数据包分析工具，使用Python和Scapy库构建，提供实时网络流量监控和分析功能。这个工具具有直观的终端界面，支持多种视图模式，适合网络安全分析、网络调试和教育用途。

## 主要功能亮点

- 🐍 实时网络数据包捕获和分析
- 🌈 美观的终端界面（使用curses实现）
- 🔍 多种视图模式：数据包列表、详细视图、十六进制视图和TCP分析
- 📊 实时网络统计信息（TCP/UDP/ICMP/HTTP/HTTPS/DNS/ARP）
- 🎯 支持BPF过滤器表达式
- 🚦 协议识别和标志分析
- ⚡ 高性能设计，支持滚动浏览历史数据包
- 🐾 可爱的动物主题图标增强可读性

## 安装指南

### 系统要求
- Python 3.6+
- Linux系统（需要root权限）
- 网络接口支持混杂模式

### 安装依赖
```bash
# 安装必要的依赖
sudo apt-get update
sudo apt-get install python3 python3-pip libpcap-dev

# 安装Python依赖包
pip install scapy curses argparse
```

### 获取代码
```bash
git clone https://github.com/yourusername/terminal-packet-sniffer.git
cd terminal-packet-sniffer
```

## 使用方法

### 基本使用
```bash
sudo python3 terminal_sniffer.py
```

### 带参数使用
```bash
sudo python3 terminal_sniffer.py -i eth0 -f "tcp port 80" -c 2000
```

### 命令行参数
| 参数 | 简写 | 描述 | 示例 |
|------|------|------|------|
| `--interface` | `-i` | 指定网络接口 | `-i eth0` |
| `--filter` | `-f` | 设置BPF过滤器表达式 | `-f "tcp port 80"` |
| `--count` | `-c` | 设置最大保留数据包数量 | `-c 2000` |

### 界面操作指南
程序启动后，你会看到一个美观的终端界面，分为三个主要区域：

1. **顶部状态栏**：显示统计信息和过滤条件
2. **主内容区**：根据当前视图模式显示数据包信息
3. **底部控制栏**：显示可用的快捷键

#### 主视图模式
- **列表视图**：显示捕获的数据包摘要
- **详情视图**：显示选定数据包的详细信息
- **十六进制视图**：显示数据包的十六进制转储
- **TCP分析视图**：深入分析TCP协议细节

#### 快捷键列表
| 快捷键 | 功能描述 |
|--------|----------|
| `Q` | 退出程序 |
| `S` | 开始/停止捕获 |
| `C` | 清除所有捕获的数据包 |
| `↑/↓` | 在列表视图中导航 |
| `PgUp/PgDn` | 快速滚动数据包列表 |
| `Enter` | 查看选定数据包的详情 |
| `H` | 切换到十六进制视图 |
| `T` | 切换到TCP分析视图 |
| `ESC` | 返回列表视图 |
| `Tab` | 在详细视图模式间循环 |

## 界面说明

### 数据包列表视图
![Packet List View](screenshots/list-view.png)

列表视图显示以下信息：
1. 序号：捕获的数据包编号
2. 时间：数据包捕获时间（精确到毫秒）
3. 源地址：数据包来源IP地址
4. 目标地址：数据包目标IP地址
5. 协议：使用的网络协议（带图标）
6. 长度：数据包大小（字节）
7. 信息：协议特定信息（端口、标志等）

### 数据包详情视图
![Detail View](screenshots/detail-view.png)

详情视图显示：
- 基本数据包信息（时间、源/目的地址、协议等）
- 协议层次分析
- 有效负载类型检测
- 协议特定标志分析

### 十六进制视图
![Hex View](screenshots/hex-view.png)

十六进制视图显示：
- 数据包的完整十六进制转储
- ASCII解码的对应内容
- 按行组织的十六进制数据

### TCP分析视图
![TCP Analysis](screenshots/tcp-analysis.png)

TCP分析视图提供：
- TCP头部字段详细解析
- TCP标志位状态（SYN, ACK, FIN, RST等）
- 窗口大小和校验和信息
- 有效负载分析和协议检测

## 注意事项

1. **需要root权限**：数据包捕获需要管理员权限
   ```bash
   sudo python3 terminal_sniffer.py
   ```

2. **选择正确的网络接口**：使用`-i`参数指定要监控的接口
   ```bash
   sudo python3 terminal_sniffer.py -i eth0
   ```

3. **使用过滤器**：合理使用BPF过滤器减少不必要的数据
   ```bash
   # 只捕获HTTP流量
   sudo python3 terminal_sniffer.py -f "tcp port 80"
   
   # 只捕获特定主机的流量
   sudo python3 terminal_sniffer.py -f "host 192.168.1.100"
   ```

4. **性能考虑**：在高速网络环境下，适当限制保留的数据包数量
   ```bash
   # 只保留最近1000个数据包
   sudo python3 terminal_sniffer.py -c 1000
   ```

## 开发与贡献

欢迎贡献代码！请遵循以下步骤：

1. Fork项目仓库
2. 创建特性分支 (`git checkout -b feature/your-feature`)
3. 提交更改 (`git commit -am 'Add some feature'`)
4. 推送到分支 (`git push origin feature/your-feature`)
5. 创建Pull Request

## 许可证

本项目采用 [MIT 许可证](LICENSE)

## 致谢

- Scapy项目团队 - 强大的数据包操作库
- Python curses库开发者 - 终端界面支持
- 所有贡献者和用户

---

**Happy Sniffing!** 🐍🔍🌐
