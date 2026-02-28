# 日志输出优化 - 简洁模式

## 问题
用户报告 AI 控制台的输出噪音太多，影响可读性。

## 解决方案
在 AutoTestWorker 中实现日志级别控制（verbose 参数），支持两种模式：
- **简洁模式** (verbose=False) — 仅显示关键结果，默认启用
- **详细模式** (verbose=True) — 显示所有细节日志

## 实现细节

### 1. 修改 AutoTestWorker
**文件**：`src/gui/workers/auto_test_worker.py`

#### 添加 verbose 参数
```python
def __init__(self, url, cmd, fp_timeout, send_timeout, do_port_scan: bool = False,
             ports: list = None, port_timeout: int = 2, verbose: bool = False):
    # ...
    self.verbose = verbose
```

#### 添加条件日志方法
```python
def _log(self, msg: str, force: bool = False):
    """
    条件性日志输出。
    force=True 时无视 verbose 设置，始终输出（用于关键信息）
    """
    if self.verbose or force:
        self.log_signal.emit(msg)
```

#### 使用条件日志替代直接 emit
所有日志调用改为：
```python
# 详细信息：仅在 verbose=True 时显示
self._log(f"详细信息...")

# 关键信息：始终显示
self._log(f"关键信息", force=True)
```

### 2. 修改 GUI 调用
**文件**：`poc_gui.py`

两处 AutoTestWorker 实例化都添加 `verbose=False`：

```python
# 自动化测试标签页
self.auto_worker = AutoTestWorker(
    host_input, cmd, fp_timeout, send_timeout,
    do_port_scan=do_port_scan,
    ports=ports_list,
    port_timeout=port_timeout,
    verbose=False  # 简洁输出
)

# AI 控制台
self._ai_test_worker = AutoTestWorker(
    url=host,
    cmd=cmd,
    fp_timeout=3,
    send_timeout=10,
    do_port_scan=do_port_scan,
    ports=ports,
    port_timeout=port_timeout,
    verbose=False  # 简洁输出
)
```

## 输出对比

### 简洁模式 (verbose=False) - 现在的默认行为
```
============================================================
自动化测试
============================================================
目标: 192.168.10.111
执行命令: whoami
============================================================

[*] 步骤1: 端口扫描（若启用）并对开放端口进行指纹识别...
    [+] 扫描目标: 192.168.10.111
    [+] 发现开放端口: 82, 83
    [*] 对 http://192.168.10.111:82/ 进行指纹识别...
    [*] 对 http://192.168.10.111:83/ 进行指纹识别...

[+] 匹配到的 CVE: CVE-2018-7600, CVE-2019-6340

[*] 步骤2: 执行Payload...

============================================================
[*] 尝试执行 Payload: CVE_2019_6340
    匹配端口: 83
============================================================
    [*] 目标: 192.168.10.111:83，执行命令: whoami
    [+] CVE_2019_6340 在 192.168.10.111:83 执行成功！检测到 www-data

============================================================
[*] 尝试执行 Payload: CVE_2018_7600
    匹配端口: 82, 83
============================================================
    [*] 目标: 192.168.10.111:82，执行命令: whoami
    [+] CVE_2018_7600 在 192.168.10.111:82 执行成功！检测到 www-data
    [*] 目标: 192.168.10.111:83，执行命令: whoami

============================================================
匹配到的 CVE 列表: CVE-2018-7600, CVE-2019-6340
成功执行的 CVE 数: 2/2
============================================================
```

### 详细模式 (verbose=True) - 可选
显示所有中间日志，包括：
- 每个 CSS 文件的 MD5 哈希值
- 每个端口的详细指纹匹配过程
- HTTP 响应内容摘要
- 等等...

## 关键信息（force=True）
无论 verbose 设置，以下信息始终显示：
- ✓ 初始配置（目标、命令）
- ✓ 端口扫描结果
- ✓ CVE 匹配结果
- ✓ Payload 执行结果（成功/失败）
- ✓ 最终统计（成功 CVE 数）

## 使用指南

### 切换到详细模式
如果用户需要完整的诊断日志，可以：
1. 修改 poc_gui.py 中的两处调用，改为 `verbose=True`
2. 或为 GUI 添加一个"日志级别"选项供用户切换

### 代码示例
```python
# 简洁模式（默认）
worker = AutoTestWorker(..., verbose=False)

# 详细模式（需要诊断信息时）
worker = AutoTestWorker(..., verbose=True)
```

## 技术细节

### _log() 方法的逻辑
```
if verbose or force:
    emit log
else:
    skip
```

例如：
- `self._log("详细信息")`
  - verbose=False → 不输出
  - verbose=True → 输出

- `self._log("关键结果", force=True)`
  - 无论 verbose 值 → 都输出

## 验证

✓ 语法检查通过（py_compile）
✓ 两处 AutoTestWorker 调用都已更新
✓ 向后兼容（verbose 参数有默认值 False）

## 后续改进建议

1. **GUI 设置面板**：允许用户在设置中切换日志级别
2. **分级日志**：将日志分为 DEBUG/INFO/WARN/ERROR 多个级别
3. **日志导出**：保存完整日志到文件（包括 verbose 部分）
4. **时间戳**：添加每条日志的执行时间

---

**修改日期**：2026-02-28
**影响范围**：AutoTestWorker, poc_gui.py
**用户体验**：输出更清晰，噪音显著减少 ✨
