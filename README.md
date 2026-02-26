# CVE Payload 渗透测试工具

一个功能完整的CVE漏洞利用工具，支持自动化渗透测试、多资源指纹识别和Payload发送。本项目为毕业设计项目。

## 功能特性

- **Payload管理**: 动态加载和管理CVE Payload模块
- **自动化测试**: 端口扫描 → 指纹识别 → CVE匹配 → 自动利用
- **多资源指纹识别**: 支持CSS、JavaScript、图片、字体等多种资源类型
- **多哈希算法**: 支持MD5、SHA1、SHA256多种哈希算法
- **HTTP头指纹**: 提取Server、X-Powered-By等12种常见指纹头
- **并发下载**: 使用线程池并发下载资源，提升识别效率
- **端口扫描**: 多线程并发端口扫描
- **HTTP数据包处理**: 解析和生成HTTP请求数据包
- **双界面支持**: 命令行工具(CLI) + 图形界面(GUI)
- **指纹-CVE映射**: 支持批量操作和输入验证

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
- **资源指纹识别**: 计算CSS、JS等静态资源的多种哈希指纹
- **指纹映射**: 管理指纹-CVE映射关系（支持批量操作）
- **自动化测试**: 全自动渗透测试流程
- **端口扫描**: 可视化端口扫描

## 项目结构

```
GraduationProject/
├── README.md                   # 项目文档
├── requirements.txt            # 生产依赖
├── requirements-dev.txt        # 开发依赖
├── .gitignore                  # Git忽略规则
├── poc_tool.py                 # CLI工具入口
├── poc_gui.py                  # GUI应用入口
├── payload_sender.py           # Payload管理器
├── packet_generator.py         # HTTP数据包生成器
├── http_packet_parser.py       # HTTP数据包解析器
├── port_scanner.py             # 端口扫描模块
├── fingerprint.py              # 指纹识别模块（增强版）
├── fingerprint_cve_mapping.py  # 指纹-CVE映射管理（优化版）
├── fingerprint_cve_mapping.json # 指纹映射数据库
├── src/                        # 源代码目录
│   ├── config.py               # 配置常量
│   ├── exceptions.py           # 自定义异常
│   ├── core/                   # 核心功能模块
│   │   ├── url_utils.py        # URL工具函数
│   │   └── ai_skill.py         # AI辅助功能模块
│   ├── cli/                    # CLI界面（重构版）
│   │   ├── main.py             # CLI入口
│   │   └── commands/           # 命令处理器
│   └── gui/                    # GUI界面
│       └── workers/            # 后台工作线程
├── assets/                     # 资源文件
│   ├── background.jpg          # GUI背景图片
│   └── style.qss               # GUI样式表
└── payloads/                   # Payload模块目录
    ├── CVE_2019_6340.py
    └── CVE_2018_7600.py
```

## 核心功能详解

### 1. 多资源指纹识别

增强的指纹识别功能支持：
- **多种资源类型**: CSS、JavaScript、图片、字体文件
- **多种哈希算法**: MD5、SHA1、SHA256
- **HTTP头指纹**: Server、X-Powered-By、X-Generator等12种常见指纹头
- **并发下载**: 使用线程池提升识别效率（可配置并发数）
- **综合指纹**: 一次性获取所有指纹信息

示例：
```python
from fingerprint import get_resources_fingerprint_from_page

# 获取网站的CSS和JS资源指纹
result = get_resources_fingerprint_from_page(
    'http://example.com',
    resource_types=['css', 'js'],
    algorithms=['md5', 'sha1']
)

# 结果格式：
# {
#     'http://example.com/style.css': {
#         'md5': 'abc123...',
#         'sha1': 'def456...',
#         'cve': 'CVE-2019-1234'
#     }
# }
```

### 2. 指纹-CVE映射管理

优化的映射管理功能：
- **批量操作**: `bulk_add_mappings()` 和 `bulk_remove_mappings()`
- **输入验证**: CVE ID格式验证、MD5格式验证
- **改进的异常处理**: 使用具体的异常类型
- **配置集成**: 使用统一的配置管理

示例：
```python
from fingerprint_cve_mapping import get_manager

manager = get_manager()

# 批量添加映射
mappings = [
    {'fingerprint': 'abc123...', 'cve_id': 'CVE-2019-1234', 'description': 'Drupal RCE'},
    {'fingerprint': 'def456...', 'cve_id': 'CVE-2018-5678', 'description': 'WordPress XSS'}
]
count = manager.bulk_add_mappings(mappings)
print(f"成功添加 {count} 个映射")
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

3. （可选）实现 `verify(response, cmd: str)` 函数来自定义验证逻辑：

```python
def verify(response, cmd: str):
    """
    验证漏洞利用是否成功

    Args:
        response: HTTP响应对象
        cmd: 执行的命令

    Returns:
        bool: 是否成功
    """
    if not response:
        return False

    response_text = response.text if hasattr(response, 'text') else str(response)

    # 检查成功标志
    success_indicators = ['uid=', 'gid=', 'www-data']
    return any(indicator in response_text for indicator in success_indicators)
```

4. 工具会自动加载新的Payload模块


## 开发指南

### 代码风格

- 使用UTF-8编码
- 遵循PEP 8规范
- 函数和类使用docstring文档
- 使用类型提示提高代码可读性

### 调试模式

大多数命令支持 `--debug` 参数来显示详细的调试信息：

```bash
python poc_tool.py send CVE_2019_6340 192.168.1.1:80 whoami --debug
```

### 配置管理

项目使用统一的配置管理系统 ([src/config.py](src/config.py))：
- 超时配置
- 端口扫描配置
- 路径配置
- HTTP配置

## 重构历史

本项目经过多次重构优化：

### v1.3 - AI功能集成
- ✅ 新增 `src/core/ai_skill.py` AI辅助功能模块
- ✅ Worker 类模块化，从 poc_gui.py 迁移至 src/gui/workers/
- ✅ 清理废弃文件，精简代码结构

### v1.2 - CLI重构
- ✅ CLI逻辑模块化，迁移至 src/cli/ 目录
- ✅ poc_tool.py 精简为轻量入口
- ✅ 命令处理器独立为 src/cli/commands/ 子模块

### v1.1 - 指纹识别增强
- ✅ 支持多种资源类型（CSS、JS、图片、字体）
- ✅ 支持多种哈希算法（MD5、SHA1、SHA256）
- ✅ 添加HTTP头指纹识别
- ✅ 实现并发下载提升性能
- ✅ 优化GUI显示，按资源类型分组

### v1.0 - 基础功能
- ✅ Payload管理系统
- ✅ 自动化渗透测试
- ✅ 端口扫描
- ✅ CSS文件指纹识别
- ✅ CLI和GUI双界面

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

**版本**: v1.3
**最后更新**: 2026-02-26
