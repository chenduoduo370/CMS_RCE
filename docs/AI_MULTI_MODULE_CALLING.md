# AI 多模块功能调用 - 功能说明

## 功能概述

AI 现在可以根据用户需求调用不同的高级功能模块，而不是总是调用完整的自动化测试流程。

## 支持的功能模块

### 1. 端口扫描（##PORTSCAN##）
**触发标记**：`##PORTSCAN##{"host":"目标地址","ports":null或[端口列表],"timeout":2}##END##`

**使用场景**：
- 用户只想扫描端口
- 用户说「扫描一下端口」、「检查开放端口」等

**调用流程**：
```
用户输入 → AI 生成 ##PORTSCAN## 标记
  ↓
_check_autotest_trigger() 检测标记
  ↓
_handle_portscan_trigger() 处理
  ↓
_start_portscan_from_ai() 启动 PortScanWorker
  ↓
执行日志显示：
  ✓ [权限通过] 权限验证通过，调用 PortScanWorker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.PortScanWorker
  ℹ [调用信息] 调用参数: host=192.168.10.111, ports=null, timeout=2
  📊 [调用结果] PortScanWorker 启动成功
```

### 2. 资源指纹识别（##FINGERPRINT##）
**触发标记**：`##FINGERPRINT##{"host":"目标地址","timeout":3}##END##`

**使用场景**：
- 用户只想识别资源指纹
- 用户说「识别指纹」、「获取资源信息」等

**调用流程**：
```
用户输入 → AI 生成 ##FINGERPRINT## 标记
  ↓
_check_autotest_trigger() 检测标记
  ↓
_handle_fingerprint_trigger() 处理
  ↓
_start_fingerprint_from_ai() 启动 CSSMD5Worker
  ↓
执行日志显示：
  ✓ [权限通过] 权限验证通过，调用 CSSMD5Worker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.CSSMD5Worker
  ℹ [调用信息] 调用参数: host=192.168.10.111, timeout=3
  📊 [调用结果] CSSMD5Worker 启动成功
```

### 3. 完整渗透测试（##AUTOTEST##）
**触发标记**：`##AUTOTEST##{"host":"目标地址","cmd":"whoami","do_port_scan":true或false,"ports":[端口列表],"port_timeout":2}##END##`

**使用场景**：
- 用户想进行完整的渗透测试
- 用户说「完整测试」、「渗透测试」、「检测漏洞」等

**调用流程**：
```
用户输入 → AI 生成 ##AUTOTEST## 标记
  ↓
_check_autotest_trigger() 检测标记
  ↓
_handle_autotest_trigger() 处理
  ↓
_start_autotest_from_ai() 启动 AutoTestWorker
  ↓
执行日志显示：
  ✓ [权限通过] 权限验证通过，调用 AutoTestWorker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.AutoTestWorker
  ℹ [调用信息] 调用参数: host=192.168.10.111, cmd=whoami, do_port_scan=true, ports=null
  📊 [调用结果] AutoTestWorker 启动成功
```

## 架构设计

### 触发器分发模式

```
_check_autotest_trigger(response)
  ↓
  ├─ 检测 ##PORTSCAN## → _handle_portscan_trigger()
  │   ↓
  │   └─ _start_portscan_from_ai() → PortScanWorker
  │
  ├─ 检测 ##FINGERPRINT## → _handle_fingerprint_trigger()
  │   ↓
  │   └─ _start_fingerprint_from_ai() → CSSMD5Worker
  │
  └─ 检测 ##AUTOTEST## → _handle_autotest_trigger()
      ↓
      └─ _start_autotest_from_ai() → AutoTestWorker
```

### 权限验证流程

每个处理方法都遵循相同的权限验证流程：

```
1. 权限检查 🔍
   检测到标记，开始权限验证

2. 参数解析 ℹ
   解析 JSON 参数，验证格式

3. 参数验证 ℹ
   检查必填参数（如 host）

4. 权限通过 ✓
   验证通过，调用对应的 Worker

5. 调用信息 ℹ
   记录调用的模块和参数

6. 调用结果 📊
   记录 Worker 启动结果
```

## 使用示例

### 示例1：仅扫描端口

```
用户: 扫描一下 192.168.10.111 的端口

AI:   你好！我来帮你扫描 192.168.10.111 的端口。

     请确认以下参数：
     - 目标地址：192.168.10.111
     - 扫描模式：常用端口
     - 超时时间：2 秒

     确认执行吗？

用户: 确认

AI:   ##PORTSCAN##{"host":"192.168.10.111","ports":null,"timeout":2}##END##

执行日志：
  🔍 [权限检查] 检测到 ##PORTSCAN## 标记，开始权限验证
  ℹ [调用信息] 解析参数成功: {"host": "192.168.10.111", ...}
  ✓ [权限通过] 权限验证通过，调用 PortScanWorker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.PortScanWorker
  ℹ [调用信息] 调用参数: host=192.168.10.111, ports=null, timeout=2
  📊 [调用结果] PortScanWorker 启动成功
  ℹ [调用信息] 目标: 192.168.10.111
  ℹ [调用信息] 扫描模式: 常用端口
  ℹ [调用信息] 超时设置: 2秒

[AI执行] 开始端口扫描
  目标: 192.168.10.111
  扫描模式: 常用端口
==================================================

[+] 发现开放端口: 22, 80, 443

==================================================
[AI执行完成] 端口扫描完成
发现开放端口: [22, 80, 443]
==================================================
```

### 示例2：仅识别指纹

```
用户: 识别一下 192.168.10.111 的资源指纹

AI:   我来帮你识别 192.168.10.111 的资源指纹。

     请确认以下参数：
     - 目标地址：192.168.10.111
     - 超时时间：3 秒

     确认执行吗？

用户: 是

AI:   ##FINGERPRINT##{"host":"192.168.10.111","timeout":3}##END##

执行日志：
  🔍 [权限检查] 检测到 ##FINGERPRINT## 标记，开始权限验证
  ✓ [权限通过] 权限验证通过，调用 CSSMD5Worker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.CSSMD5Worker
  ℹ [调用信息] 调用参数: host=192.168.10.111, timeout=3
  📊 [调用结果] CSSMD5Worker 启动成功

[AI执行] 开始资源指纹识别
  目标: 192.168.10.111
==================================================

识别到 5 个资源...

==================================================
[AI执行完成] 资源指纹识别完成
识别到 5 个资源
==================================================
```

### 示例3：完整渗透测试

```
用户: 对 192.168.10.111 进行完整渗透测试，端口 82 和 83

AI:   我来帮你进行完整的渗透测试。

     请确认以下参数：
     - 目标地址：192.168.10.111
     - 指定端口：[82, 83]
     - 测试命令：whoami

     确认执行吗？

用户: 开始

AI:   ##AUTOTEST##{"host":"192.168.10.111","cmd":"whoami","do_port_scan":false,"ports":[82,83],"port_timeout":2}##END##

执行日志：
  🔍 [权限检查] 检测到 ##AUTOTEST## 标记，开始权限验证
  ✓ [权限通过] 权限验证通过，调用 AutoTestWorker（高级功能）
  ℹ [调用信息] 调用模块: src.gui.workers.AutoTestWorker
  ℹ [调用信息] 调用参数: host=192.168.10.111, cmd=whoami, do_port_scan=False, ports=[...] (2项)
  📊 [调用结果] AutoTestWorker 启动成功

[AI执行] 开始渗透测试
  目标: 192.168.10.111
  指定端口: [82, 83]
==================================================

[+] 发现开放端口: 82, 83
[+] 匹配到的 CVE: CVE-2019-6340, CVE-2018-7600
[+] CVE-2019-6340 在 192.168.10.111:83 执行成功！
[+] CVE-2018-7600 在 192.168.10.111:82 执行成功！

==================================================
[AI执行完成] 共测试 2 个CVE，2 个漏洞利用成功
==================================================
```

## 核心方法

### `_check_autotest_trigger(response: str)`
通用触发器，检测所有标记并分发到对应的处理方法。

### `_handle_portscan_trigger(response: str)`
处理端口扫描标记，验证权限并启动 PortScanWorker。

### `_handle_fingerprint_trigger(response: str)`
处理指纹识别标记，验证权限并启动 CSSMD5Worker。

### `_handle_autotest_trigger(response: str)`
处理自动化测试标记，验证权限并启动 AutoTestWorker。

### `_start_portscan_from_ai(host, ports, timeout)`
启动端口扫描，记录执行日志。

### `_start_fingerprint_from_ai(host, timeout)`
启动指纹识别，记录执行日志。

### `_start_autotest_from_ai(host, cmd, do_port_scan, ports, port_timeout)`
启动自动化测试，记录执行日志。

## 优势

✅ **灵活性**：AI 可以根据用户需求调用不同的功能
✅ **效率**：用户只需要的功能，不会执行不必要的操作
✅ **清晰性**：执行日志清楚显示调用的具体模块
✅ **可扩展性**：易于添加新的功能模块
✅ **权限控制**：每个模块都经过权限验证

## 提交信息

```
1ab3a95 功能：AI 支持调用不同的高级功能模块
```

---

**创建日期**：2026-02-28
**功能状态**：✅ 已实现
**用户体验**：灵活高效，执行日志清晰
