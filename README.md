# CVE Payload 渗透测试工具

一个功能完整的CVE漏洞利用工具，支持自动化渗透测试、指纹识别和Payload发送。本项目为毕业设计项目。

## 功能特性

- **Payload管理**: 动态加载和管理CVE Payload模块
- **自动化测试**: 端口扫描 → 指纹识别 → CVE匹配 → 自动利用
- **指纹识别**: 基于MD5的文件指纹识别和CVE映射
- **端口扫描**: 多线程并发端口扫描
- **HTTP数据包处理**: 解析和生成HTTP请求数据包
- **双界面支持**: 命令行工具(CLI) + 图形界面(GUI)

## 支持的CVE

- CVE-2019-6340: Drupal REST API RCE漏洞
- CVE-2018-7600: Drupal Form API RCE漏洞

## 系统要求

- Python 3.7+
- Windows/Linux/macOS

## 安装

1. 克隆仓库

```bash
git clone <repository-url>
cd GraduationProject
```

2. 安装依赖

```bash
pip install -r requirements.txt
```

## 快速开始

### 命令行工具 (CLI)

#### 列出可用的Payload模块

```bash
python poc_tool.py list
```

#### 显示Payload详情

```bash
python poc_tool.py show CVE_2019_6340 192.168.1.1:80 id
```

#### 发送Payload

```bash
python poc_tool.py send CVE_2019_6340 192.168.1.1:80 whoami
```

#### 端口扫描

```bash
# 扫描单个端口
python poc_tool.py portscan 192.168.1.1 -p 80

# 扫描常见端口
python poc_tool.py portscan 192.168.1.1 --common

# 扫描端口范围
python poc_tool.py portscan 192.168.1.1 -r 1-1000
```

#### 指纹识别

```bash
# 识别单个文件
python poc_tool.py fingerprint http://192.168.1.1/style.css

# 识别网站CSS文件
python poc_tool.py fingerprint http://192.168.1.1 --css
```

#### 自动化渗透测试

```bash
python poc_tool.py auto http://192.168.1.1 whoami
```

#### 生成Payload脚本

```bash
python poc_tool.py generate packet.txt CVE_2024_1234
```

### 图形界面 (GUI)

启动GUI应用：

```bash
python poc_gui.py
```

GUI提供以下功能标签页：
- **Payload测试**: 手动发送Payload
- **脚本生成**: 从HTTP数据包生成Payload模块
- **指纹识别**: 计算文件MD5指纹
- **指纹映射**: 管理指纹-CVE映射关系
- **自动化测试**: 全自动渗透测试流程
- **端口扫描**: 可视化端口扫描

## 项目结构

```
GraduationProject/
├── poc_tool.py              # CLI工具入口
├── poc_gui.py               # GUI应用入口
├── payload_sender.py        # Payload管理器
├── packet_generator.py      # HTTP数据包生成器
├── http_packet_parser.py    # HTTP数据包解析器
├── port_scanner.py          # 端口扫描模块
├── fingerprint.py           # 指纹识别模块
├── fingerprint_cve_mapping.py  # 指纹-CVE映射管理
├── fingerprint_cve_mapping.json # 指纹映射数据库
└── payloads/                # Payload模块目录
    ├── CVE_2019_6340.py
    └── CVE_2018_7600.py
```

## 添加新的Payload

1. 在 `payloads/` 目录下创建新的Python文件，例如 `CVE_XXXX_XXXX.py`

2. 实现 `build(ip_port: str, cmd: str)` 函数：

```python
def build(ip_port: str, cmd: str):
    """
    构建Payload数据

    Args:
        ip_port: 目标IP和端口，格式为 "192.168.1.1:80"
        cmd: 要执行的命令

    Returns:
        dict: 包含method, url, headers, data的字典
    """
    return {
        "method": "POST",
        "url": f"http://{ip_port}/vulnerable/path",
        "headers": {
            "Content-Type": "application/json",
            "Host": ip_port
        },
        "data": f'{{"cmd": "{cmd}"}}'
    }
```

3. 工具会自动加载新的Payload模块

## 指纹识别和CVE映射

### 添加指纹映射

```bash
python poc_tool.py fingerprint http://example.com/style.css --add CVE_2019_6340
```

### 查询指纹对应的CVE

```bash
python poc_tool.py fingerprint http://example.com/style.css --query
```

### 删除指纹映射

```bash
python poc_tool.py fingerprint <md5_hash> --delete
```

## 开发指南

### 代码风格

- 使用UTF-8编码
- 遵循PEP 8规范
- 函数和类使用docstring文档

### 调试模式

大多数命令支持 `--debug` 参数来显示详细的调试信息：

```bash
python poc_tool.py send CVE_2019_6340 192.168.1.1:80 whoami --debug
```

## 注意事项

⚠️ **重要提示**

- 本工具仅用于授权的安全测试和教育目的
- 未经授权对他人系统进行渗透测试是违法行为
- 使用本工具造成的任何后果由使用者自行承担
- 请遵守当地法律法规和网络安全法

## 许可证

本项目仅供学习和研究使用。

## 贡献

欢迎提交Issue和Pull Request。

## 联系方式

如有问题或建议，请通过Issue联系。

---

**版本**: v1.1
**最后更新**: 2026-02-09
