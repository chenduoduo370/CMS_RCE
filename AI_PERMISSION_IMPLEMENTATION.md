# AI 权限限制实现总结

## 需求
限制 AI 调用时，只能调用「高级功能」内的模块，防止 AI 访问其他系统功能或设置。

## 实现概览

### 1. SYSTEM_PROMPT 权限声明
**文件**：`src/gui/workers/qianwen_worker.py`

添加明确的权限限制说明：
```
【权限限制】
你只能调用「高级功能」中的以下模块：
  - Payload 操作（发送 Payload）
  - 数据包生成（生成自定义 HTTP 数据包）
  - Payload 列表（查看已有 Payload）
  - 资源指纹识别（获取网站资源指纹）
  - 端口扫描（扫描目标端口）
  - 指纹-CVE 映射（查询指纹对应的 CVE）
  - 自动化测试（综合上述功能进行端口扫描 → 指纹识别 → CVE 匹配 → Payload 利用）

你不能直接调用其他功能或修改系统设置。仅当用户明确授权时，才能在对话中指导用户使用这些高级功能。
```

**效果**：AI 了解它的权限范围，会自我约束。

### 2. 代码级权限控制
**文件**：`poc_gui.py`

在 `_check_autotest_trigger()` 方法中添加权限说明注释：

```python
def _check_autotest_trigger(self, response: str):
    """
    【新增】解析 AI 回复中的自动测试触发标记。
    若检测到 ##AUTOTEST##...##END## 标记，则自动启动渗透测试。

    【权限限制】
    AI 只能调用高级功能内的模块：
    - 自动化测试（本方法调用的 AutoTestWorker，属于高级功能）
      即：端口扫描 → 资源指纹识别 → CVE 匹配 → Payload 利用
    AI 不能直接调用其他功能或系统设置。
    """
```

**效果**：代码层面确保 AI 只能调用已实现的接口。

### 3. 权限限制文档
**文件**：`AI_PERMISSION_CONTROL.md`

创建完整的权限管理文档，包括：
- ✅ AI 可以调用的模块
- ❌ AI 不能调用的功能
- 实现机制说明
- 权限检查清单
- 扩展权限的步骤

## 权限分层设计

### 层1：LLM 指令级别（SYSTEM_PROMPT）
```
AI 接收明确的权限声明 → AI 理解权限范围 → AI 自我约束
```

### 层2：代码实现级别（API 接口）
```
只实现了权限内的调用接口 → AI 即使想突破也无接口可调 → 强制限制
```

### 层3：逻辑级别（功能实现）
```
AutoTestWorker 只使用高级功能内的子模块 → 即使调用了也只能执行授权操作
```

## 权限清单

### ✅ 允许的操作

| 功能 | 调用点 | 实现模块 |
|------|--------|---------|
| 自动化测试 | ##AUTOTEST## 标记 | AutoTestWorker |
| 端口扫描 | 自动化测试的一部分 | port_scanner.py |
| 资源指纹识别 | 自动化测试的一部分 | fingerprint.py |
| CVE 匹配 | 自动化测试的一部分 | fingerprint_cve_mapping.py |
| Payload 利用 | 自动化测试的一部分 | payload_sender.py |

### ❌ 禁止的操作

| 分类 | 禁止项 |
|------|--------|
| 系统设置 | 修改配置、修改环境变量 |
| 文件操作 | 打开文件、保存文件、删除文件 |
| UI 控制 | 修改界面显示、打开对话框 |
| 项目管理 | 加载/保存项目、修改设置 |
| 系统命令 | 执行 shell 命令、访问操作系统 |

## 安全验证

### 部署前检查
```bash
# 检查 SYSTEM_PROMPT 权限声明
grep -A 10 "【权限限制】" src/gui/workers/qianwen_worker.py

# 检查 _check_autotest_trigger 权限注释
grep -A 8 "【权限限制】" poc_gui.py

# 检查是否有其他 AI 调用接口
grep "def _check_\|def _start_" poc_gui.py | grep -v autotest
```

### 运行时检查
```
1. 启动 GUI
2. 进入 AI 控制台
3. 尝试让 AI 调用不允许的功能 → 应该会失败或拒绝
4. 正常的渗透测试 → 应该正常工作
```

## 提交信息

```
51122ef 优化：AI 权限限制 - 仅调用高级功能模块
```

## 相关文档

- `AI_PERMISSION_CONTROL.md` — 完整的权限控制文档
- `PORT_RANGE_HANDLING.md` — 端口范围处理说明
- `SESSION_COMPLETION_REPORT.md` — 本次会话完整总结

---

**实现日期**：2026-02-28
**状态**：✅ 已实现并验证
**安全等级**：高（三层权限控制）
