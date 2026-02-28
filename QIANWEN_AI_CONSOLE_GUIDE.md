# 千问 AI 控制台 - 使用指南

## 概述
项目已集成阿里云千问大模型（OpenAI Compatible API），实现 GUI 中的 AI 对话控制台。支持流式输出、多轮对话、配置持久化。

## 快速开始

### 1. 准备 API Key
访问 [阿里云百炼](https://bailian.aliyun.com/)：
- 使用主账号登录
- 进入 API Key 管理页面（支持北京/新加坡/弗吉尼亚区域）
- 创建新的 API Key
- 复制 `sk-` 开头的 Key

### 2. 启动 GUI
```bash
python poc_gui.py
```

### 3. 进入 AI 控制台标签页
- 启动后点击"AI 控制台"标签
- 看到欢迎信息即为加载成功

### 4. 配置 API Key
- 在"千问 API 配置"区域输入 API Key
- 选择模型（qwen-plus / qwen-turbo / qwen-max）
- 点击"保存配置"（可选）

### 5. 开始对话
- 在"输入消息"区域输入问题
- 方式一：点击"发送"按钮
- 方式二：按 `Ctrl+Enter` 快捷键
- 流式文本逐字显示在"对话记录"区

## UI 说明

### 配置区域
| 项目 | 说明 |
|------|------|
| API Key | 阿里云千问 API Key（密码模式显示） |
| 模型 | 选择 qwen-plus/turbo/max（推荐 qwen-plus） |
| 保存配置 | 将 Key 和模型保存到 ai_config.json |
| 加载配置 | 从 ai_config.json 读取已保存配置 |

### 对话显示区
- 只读文本框
- 显示完整对话历史
- 左对齐显示用户消息，自动格式化

### 输入区
| 项目 | 功能 |
|------|------|
| 输入框 | 支持多行文本，字符计数实时显示 |
| 发送 | 启动 Worker 发送消息（期间按钮禁用） |
| 停止 | 中断当前流式输出（正在对话时启用） |
| 清空对话 | 确认后清空历史和显示区 |

## 配置持久化

### 保存位置
`{项目根目录}/ai_config.json`

### 文件格式
```json
{
  "api_key": "sk-your-api-key-here",
  "model": "qwen-plus"
}
```

### 自动加载
- 启动 GUI 时自动静默加载已保存配置
- 如无配置文件则使用默认值

### 安全性说明
- API Key 明文保存在 ai_config.json（用户知情）
- 建议不提交该文件到版本控制
- 如 Key 泄露应立即在百炼平台删除

## 技术细节

### 流式输出实现
- 使用 `QTextCursor.insertText()` 而非 `append()`
- 避免每个 token 换行，实现真正的流式显示
- 自动滚动到最新内容

### 多轮对话上下文
```
消息队列结构：
[
  {"role": "system", "content": "渗透测试助手..."},
  {"role": "user", "content": "第一个问题"},
  {"role": "assistant", "content": "第一个回答"},
  {"role": "user", "content": "第二个问题"},
  ...
]
```
- 第一轮自动插入 system message
- 每轮对话完成后持久化到内存
- 清空对话时重置整个队列

### Worker 线程模型
- 继承 `QThread`，遵循 Qt 线程安全规范
- `token_signal` 发射每个流式 token
- `finished` 信号确保按钮总能解锁（即使异常）
- `error` 信号处理 API 错误和库缺失

### API 兼容性
- **Base URL**: `https://dashscope.aliyuncs.com/compatible-mode/v1`
- **模型名**: `qwen-plus`、`qwen-turbo`、`qwen-max`
- **认证方式**: `Authorization: Bearer {api_key}`
- **Streaming**: `stream=True` 完全支持

## 常见问题

### Q: openai 库未安装怎么办？
A: 运行以下命令：
```bash
pip install openai>=1.0.0
```

### Q: 如何切换模型？
A:
1. 在模型下拉框选择新模型
2. 点"保存配置"（可选）
3. 重新发送消息时生效

### Q: API Key 错误提示什么？
A: 检查：
- Key 格式是否为 `sk-` 开头
- 是否复制完整
- 在百炼平台是否已启用
- 配额是否充足

### Q: 能否离线使用？
A: 不能。必须有有效 API Key 和网络连接。

### Q: 历史记录会有多长？
A: 当前无自动截断。建议不超过 20 轮对话（防止 token 超限）。
超出限制时可点"清空对话"重新开始。

### Q: 支持中文吗？
A: 完全支持。UI 和 API 都使用中文。

## 故障排查

| 问题 | 排查步骤 |
|------|---------|
| GUI 启动时闪退 | 检查 PyQt5 是否安装（`pip install PyQt5>=5.15.0`） |
| 无法发送消息 | 检查 API Key 是否输入、网络是否连接 |
| 流式输出不显示 | 检查 openai 库是否安装 |
| 配置无法保存 | 检查项目目录是否有写权限 |
| 对话中止 | 点"停止"按钮可中断，允许重新发送 |

## 性能参考

| 指标 | 值 |
|------|-----|
| 连接超时 | 10 秒 |
| 单个 token 延迟 | < 100 ms（通常 50ms 内） |
| 最大对话轮数 | 建议 <= 20 轮 |
| 单次消息最大长度 | 理论无限（实际受 API 限制） |

## 相关文件

- `src/gui/workers/qianwen_worker.py` — QianwenWorker 线程实现
- `src/config.py` — QIANWEN_* 配置常量
- `poc_gui.py` — create_ai_console_tab() 及辅助方法
- `requirements.txt` — openai>=1.0.0 依赖

## 版本信息
- 项目版本: v1.5
- 千问适配: 2026-02-28
- openai SDK: >=1.0.0
- PyQt5: >=5.15.0
