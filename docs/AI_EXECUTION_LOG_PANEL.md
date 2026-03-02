# AI 执行日志面板 - 功能说明

## 功能概述

在 AI 控制台右侧添加了一个新的「AI 执行日志」面板，用于实时记录和显示 AI 调用的代码信息和权限验证过程。

## UI 布局

### AI 控制台标签页结构

```
┌─────────────────────────────────────────────────────────────┐
│  千问 API 配置                                              │
│  [API Key] [模型] [保存配置] [加载配置]                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────────────┐  ┌──────────────────────┐   │
│  │   对话记录（左侧）        │  │  AI 执行日志（右侧）  │   │
│  │                          │  │                      │   │
│  │  [对话内容显示区]        │  │  [执行日志显示区]    │   │
│  │                          │  │                      │   │
│  │  ┌──────────────────────┐│  │  ┌──────────────────┐│   │
│  │  │ 输入消息              ││  │  │ [清空日志]       ││   │
│  │  │ [输入框]              ││  │  └──────────────────┘│   │
│  │  │ [发送] [停止] [清空]  ││  │                      │   │
│  │  └──────────────────────┘│  │                      │   │
│  └──────────────────────────┘  └──────────────────────┘   │
│  比例：2:1（对话区占 2/3，日志区占 1/3）                   │
└─────────────────────────────────────────────────────────────┘
```

## 日志类型和颜色

| 日志类型 | 符号 | 颜色 | 含义 |
|---------|------|------|------|
| permission_check | 🔍 | 蓝色 | 权限检查中 |
| permission_pass | ✓ | 绿色 | 权限验证通过 |
| permission_deny | ✗ | 红色 | 权限被拒绝 |
| call_info | ℹ | 蓝色 | 调用信息 |
| call_result | 📊 | 紫色 | 调用结果 |

## 日志记录流程

### 1. 权限检查阶段

当 AI 输出 `##AUTOTEST##` 标记时：

```
🔍 [权限检查] 14:23:45: 检测到 ##AUTOTEST## 标记，开始权限验证
ℹ [调用信息] 14:23:45: 解析参数成功: {"host":"192.168.10.111",...}
✓ [权限通过] 14:23:45: 权限验证通过，调用 AutoTestWorker（高级功能）
ℹ [调用信息] 14:23:45: 调用模块: src.gui.workers.AutoTestWorker
ℹ [调用信息] 14:23:45: 调用参数: host=192.168.10.111, cmd=whoami, do_port_scan=true, ports=null
```

### 2. 执行阶段

当 AutoTestWorker 启动时：

```
📊 [调用结果] 14:23:46: AutoTestWorker 启动成功
ℹ [调用信息] 14:23:46: 目标: 192.168.10.111
ℹ [调用信息] 14:23:46: 端口扫描: True
ℹ [调用信息] 14:23:46: 超时设置: 2秒
```

### 3. 权限拒绝示例

如果 AI 尝试调用不允许的功能：

```
🔍 [权限检查] 14:24:00: 检测到非法标记
✗ [权限拒绝] 14:24:00: 标记格式错误，权限拒绝
```

## 核心方法

### `_log_ai_exec(log_type, message)`

记录 AI 执行日志的主方法。

**参数**：
- `log_type` (str): 日志类型
  - `"permission_check"` - 权限检查
  - `"permission_pass"` - 权限通过
  - `"permission_deny"` - 权限拒绝
  - `"call_info"` - 调用信息
  - `"call_result"` - 调用结果

- `message` (str): 日志消息

**示例**：
```python
self._log_ai_exec("permission_pass", "权限验证通过，调用 AutoTestWorker")
self._log_ai_exec("call_info", f"目标: {host}")
self._log_ai_exec("permission_deny", "权限被拒绝")
```

### `_clear_ai_exec_log()`

清空执行日志面板。

**行为**：
1. 弹出确认对话框
2. 用户确认后清空日志
3. 显示欢迎信息

## 权限验证流程

### 正常流程（权限通过）

```
用户输入 → AI 生成 ##AUTOTEST## 标记
  ↓
_check_autotest_trigger() 检测标记
  ↓
🔍 [权限检查] 检测到标记
  ↓
ℹ [调用信息] 解析参数
  ↓
✓ [权限通过] 验证通过
  ↓
ℹ [调用信息] 记录调用模块和参数
  ↓
_start_autotest_from_ai() 启动 AutoTestWorker
  ↓
📊 [调用结果] 记录启动结果
```

### 异常流程（权限拒绝）

```
AI 尝试调用不允许的功能
  ↓
_check_autotest_trigger() 检测异常
  ↓
✗ [权限拒绝] 记录拒绝原因
  ↓
用户看到红色警告信息
```

## 使用场景

### 场景1：验证 AI 权限

用户可以通过执行日志面板验证：
- ✅ AI 是否只调用了高级功能模块
- ✅ 调用的参数是否正确
- ✅ 权限验证是否通过

### 场景2：调试 AI 行为

当 AI 的行为异常时，用户可以：
- 查看执行日志了解 AI 调用了什么
- 检查参数是否正确传递
- 识别权限拒绝的原因

### 场景3：安全审计

系统管理员可以：
- 审计 AI 的所有调用记录
- 检查是否有权限突破尝试
- 验证权限控制是否有效

## 日志持久化

当前实现中，日志存储在内存中（`self._ai_exec_log` 列表）。

### 可选的增强功能

如果需要持久化日志，可以：

1. **保存到文件**：
```python
def _save_ai_exec_log(self, filename):
    import json
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(self._ai_exec_log, f, ensure_ascii=False, indent=2)
```

2. **导出为 CSV**：
```python
def _export_ai_exec_log_csv(self, filename):
    import csv
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['timestamp', 'type', 'message'])
        writer.writeheader()
        writer.writerows(self._ai_exec_log)
```

3. **导出为 HTML 报告**：
```python
def _export_ai_exec_log_html(self, filename):
    html = "<html><body><table border='1'>"
    for log in self._ai_exec_log:
        html += f"<tr><td>{log['timestamp']}</td><td>{log['type']}</td><td>{log['message']}</td></tr>"
    html += "</table></body></html>"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)
```

## 技术细节

### 颜色实现

使用 HTML 标签实现彩色输出：

```python
colored_msg = f"<span style='color: green;'>{prefix} {timestamp}: {message}</span>"
self.qw_exec_log_display.insertHtml(f"\n{colored_msg}")
```

### 时间戳

每条日志都包含时间戳（精确到秒）：

```python
timestamp = __import__('datetime').datetime.now().strftime("%H:%M:%S")
```

### 日志列表

内存中维护完整的日志列表，便于后续查询和导出：

```python
self._ai_exec_log.append({
    "timestamp": timestamp,
    "type": log_type,
    "message": message
})
```

## 相关文件

- `poc_gui.py` - 主 GUI 文件，包含执行日志面板实现
- `AI_PERMISSION_CONTROL.md` - 权限控制文档
- `AI_PERMISSION_IMPLEMENTATION.md` - 权限实现细节

## 提交信息

```
3ca0142 功能：添加 AI 执行日志面板
```

---

**创建日期**：2026-02-28
**功能状态**：✅ 已实现
**用户体验**：可实时查看 AI 调用的代码和权限验证过程
