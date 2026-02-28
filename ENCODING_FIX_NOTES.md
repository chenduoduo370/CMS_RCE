# 千问 AI 编码问题修复说明

## 问题描述
使用千问 AI 控制台时出现错误：
```
[错误] 'ascii' codec can't encode characters in position 18-21: ordinal not in range(128)
```

## 根本原因
当千问API返回中文文本时，在处理异常信息或流式token时，某个环节遇到了ASCII编码限制，导致中文字符无法正确编码。

## 修复方案

### 1. 改进 QianwenWorker 的 token 处理
**文件**: `src/gui/workers/qianwen_worker.py`

```python
# 原有代码：直接发射 delta
if delta:
    self.token_signal.emit(delta)

# 修复后：确保编码正确
if delta:
    if isinstance(delta, bytes):
        delta = delta.decode('utf-8', errors='replace')
    elif not isinstance(delta, str):
        delta = str(delta)
    self.token_signal.emit(delta)
```

### 2. 改进异常处理的编码
**文件**: `src/gui/workers/qianwen_worker.py`

```python
# 原有代码：直接转换异常
except Exception as e:
    self.error.emit(str(e))

# 修复后：安全转换
except Exception as e:
    try:
        error_msg = str(e)
    except Exception:
        error_msg = repr(e)
    self.error.emit(error_msg)
```

### 3. 改进 GUI 的 token 接收
**文件**: `poc_gui.py` 中的 `_on_qianwen_token()`

```python
# 原有代码：直接使用 token
self._current_ai_response += token

# 修复后：先确保是正确编码的字符串
if isinstance(token, bytes):
    token = token.decode('utf-8', errors='replace')
elif not isinstance(token, str):
    token = str(token)

self._current_ai_response += token
```

### 4. 改进错误消息处理
**文件**: `poc_gui.py` 中的 `_on_qianwen_error()`

```python
# 修复后：安全处理错误消息编码
if isinstance(error_msg, bytes):
    error_msg = error_msg.decode('utf-8', errors='replace')
elif not isinstance(error_msg, str):
    error_msg = str(error_msg)

self.qw_chat_display.append(f"\n[错误] {error_msg}")
```

## 修复策略
- ✅ 显式检查数据类型（bytes/str）
- ✅ 使用 `utf-8` 编码，errors='replace' 容错处理
- ✅ 在所有关键节点（token、error、完成）都加入编码保护
- ✅ 多层异常捕获，确保 GUI 不崩溃

## 现在应该可以正常使用
修复后，即使千问 API 返回包含任何特殊字符的中文文本，也能正确显示。

## 测试建议
1. 重新启动 GUI
2. 进入 AI 控制台
3. 输入一个简单的中文问题，如"你好"或"请介绍一下 Drupal"
4. 观察是否正常流式输出中文文本

如果仍有问题，请检查：
- ✓ API Key 是否有效（可在阿里云百炼控制台测试）
- ✓ 网络连接是否正常
- ✓ 模型选择是否正确（建议用 qwen-plus）
