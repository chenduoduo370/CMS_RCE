# AI 权限限制 - 仅调用高级功能模块

## 目的
确保 AI 只能调用「高级功能」中已授权的模块，防止 AI 访问其他系统功能或设置。

## 权限划分

### ✅ AI 可以调用的模块（高级功能内）

#### 1. 自动化测试（AutoTestWorker）
- **功能**：综合进行端口扫描、资源指纹识别、CVE 匹配、Payload 利用
- **调用点**：`_check_autotest_trigger()` → `_start_autotest_from_ai()` → `AutoTestWorker`
- **参数**：host, cmd, do_port_scan, ports, port_timeout
- **日志输出**：到 AI 对话区实时显示
- **触发方式**：AI 输出 `##AUTOTEST##...##END##` 标记

#### 2. 高级功能子模块（通过 SYSTEM_PROMPT 指导）
虽然当前 AI 自动调用的是「自动化测试」，但 SYSTEM_PROMPT 明确告知 AI，它有权访问以下模块供用户询问：
- Payload 操作
- 数据包生成
- Payload 列表
- 资源指纹识别
- 端口扫描
- 指纹-CVE 映射

AI 可以在对话中指导用户使用这些功能，但自动触发仅限于「自动化测试」。

### ❌ AI 不能调用的功能

#### 系统范围
- [ ] 项目设置（settings）
- [ ] 数据库管理
- [ ] 配置文件修改
- [ ] 日志文件访问
- [ ] 系统环境变量修改

#### 其他 UI 功能
- [ ] 打开文件对话框（FileDialog）
- [ ] 修改 GUI 显示
- [ ] 保存/加载项目文件
- [ ] 修改用户设置

#### 已删除的功能
- [ ] AI 验证功能（已在 2026-02-28 删除）
- [ ] 多轮对话验证（已移除）

## 实现机制

### 代码级别的权限控制

#### 文件：`src/gui/workers/qianwen_worker.py`

**SYSTEM_PROMPT 中的权限声明**：
```python
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

#### 文件：`poc_gui.py`

**方法级别的权限控制**：
```python
def _check_autotest_trigger(self, response: str):
    """
    【权限限制】
    AI 只能调用高级功能内的模块：
    - 自动化测试（本方法调用的 AutoTestWorker，属于高级功能）
      即：端口扫描 → 资源指纹识别 → CVE 匹配 → Payload 利用
    AI 不能直接调用其他功能或系统设置。
    """
```

## 执行流程

### 正常的权限内调用
```
用户对话
  ↓
AI 理解用户意图（渗透测试）
  ↓
AI 按照 SYSTEM_PROMPT 步骤引导用户收集参数
  ↓
用户确认参数
  ↓
AI 输出 ##AUTOTEST## 标记
  ↓
_check_autotest_trigger() 解析标记
  ↓
_start_autotest_from_ai() 创建 AutoTestWorker
  ↓
AutoTestWorker 执行测试（高级功能内）
  ✅ 成功（权限范围内）
```

### 超出权限的调用企图
```
AI 尝试调用非高级功能模块
  或
AI 尝试修改系统设置
  或
AI 尝试访问不授权的功能
  ↓
SYSTEM_PROMPT 中的规则阻止
  或
代码中没有对应的调用接口
  ↓
❌ 失败（权限被拒绝）
```

## 权限检查清单

### 部署前验证
- [ ] SYSTEM_PROMPT 包含明确的权限限制声明
- [ ] `_check_autotest_trigger()` 仅调用 AutoTestWorker
- [ ] AutoTestWorker 只使用高级功能内的子模块
- [ ] 没有其他方法与 AI 直接交互
- [ ] 所有文件访问/修改操作都在 try-except 中

### 运行时验证
- [ ] AI 无法调用文件对话框
- [ ] AI 无法修改配置文件
- [ ] AI 无法访问系统设置
- [ ] AI 只能输出 ##AUTOTEST## 标记来触发自动化测试
- [ ] 所有日志都定向到 AI 对话区（不写入文件）

## 扩展权限的步骤（如果将来需要）

如果未来需要授予 AI 更多权限（如调用其他高级功能），遵循以下流程：

1. **在 SYSTEM_PROMPT 中声明**：添加新的功能权限说明
2. **创建新的触发标记**：如 `##PAYLOAD##...##END##`、`##PORTSCAN##...##END##`
3. **添加解析方法**：在 `poc_gui.py` 中添加对应的 `_check_xxx_trigger()`
4. **创建调用方法**：添加 `_start_xxx_from_ai()` 来调用对应的 Worker
5. **添加测试用例**：验证新功能的权限限制
6. **更新文档**：在本文件中记录新权限

## 安全建议

### 当前安全措施
- ✅ SYSTEM_PROMPT 明确限制权限范围
- ✅ 代码级别只实现了权限内的调用接口
- ✅ 没有提供 AI 与文件系统交互的接口
- ✅ 没有提供 AI 与系统命令执行的接口
- ✅ 所有 AI 触发的操作都在可控的 Worker 线程中

### 进一步强化建议
1. **添加权限日志**：记录 AI 所有的调用尝试（成功和失败）
2. **添加权限审计**：定期检查是否有异常的权限请求
3. **添加速率限制**：限制 AI 单位时间内的调用频率
4. **定期安全审查**：定期检查 SYSTEM_PROMPT 中的权限规则是否仍然适当

## 相关文件

- `src/gui/workers/qianwen_worker.py` — SYSTEM_PROMPT 权限声明
- `poc_gui.py` — 权限执行的代码实现
- `src/gui/workers/auto_test_worker.py` — 高级功能实现（自动化测试）

---

**创建日期**：2026-02-28
**最后更新**：2026-02-28
**版本**：v1.0
**状态**：✅ 已实现
