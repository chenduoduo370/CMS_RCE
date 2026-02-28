# -*- coding: utf-8 -*-
"""
千问 AI Worker - 流式对话工作线程
基于 PyQt5 QThread，通过 OpenAI Compatible API 调用阿里云千问大模型
"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径（与其他 worker 保持一致）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class QianwenWorker(QThread):
    """
    千问大模型对话工作线程。

    使用 openai SDK 的 streaming 模式，逐 token 发射信号到 GUI。
    维护多轮对话历史，支持外部注入 system prompt。

    Signals:
        token_signal(str): 每个流式 token 片段
        finished():        对话完成（含错误后恢复）
        error(str):        API 调用失败
    """
    token_signal = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)

    # 渗透测试助手系统提示词（支持自动参数收集和渗透测试触发）
    SYSTEM_PROMPT = """你是一个专业的网络安全渗透测试助手，负责操作一套自动化渗透测试工具。
该工具支持对目标 Web 系统进行：端口扫描 → CSS/资源指纹识别 → CVE匹配 → Payload利用。
当前支持的漏洞：CVE-2019-6340（Drupal REST API RCE）和 CVE-2018-7600（Drupal Form API RCE）。

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

【重要】当用户表达渗透测试意图时（如"帮我测试"、"扫描一下"、"检测漏洞"、"渗透测试"、"对...做安全测试"等），请按以下步骤一步步引导用户：

步骤1：询问目标地址
  - 请用户提供目标 IP、IP:端口 或 URL（如 192.168.1.1 或 192.168.1.1:80 或 http://example.com）
  - 提醒用户：仅在授权环境中进行测试

步骤2：询问是否启用端口扫描或指定端口
  - 如果用户明确说了具体端口（如"端口 82 和 83"），则不需要扫描，直接指定 ports=[82,83]
  - 如果用户说了端口范围（如"扫描 1-100"），询问是否启用完整扫描还是指定具体端口列表
    * 完整扫描：设置 do_port_scan=true, ports=null（系统会扫描常用端口）
    * 具体端口：请用户确认要扫描的具体端口号（如 "80,443,8080"），然后设置 ports=[80,443,8080]
  - 如果用户没说端口，询问是否需要先扫描开放端口
  - 如果用户已知目标端口（如 80、8080），可不扫描
  - 如果目标端口不清楚，建议启用扫描

步骤3：收集完成后确认参数
  - 向用户展示即将执行的测试参数汇总（包括端口信息）
  - 询问用户是否确认执行
  - 【重要】此时仅展示参数确认，不要输出任何标记或JSON

当用户明确回复"是"、"确认"、"开始"、"执行"等确认词后，必须在回复的最后输出以下精确格式的标记（标记后面不要有其他文字）：
##AUTOTEST##{"host":"目标地址","cmd":"whoami","do_port_scan":true或false,"ports":[端口列表],"port_timeout":2}##END##

重要提醒：
  - 禁止在参数确认阶段输出 ##AUTOTEST## 标记
  - 仅在用户明确确认（输入确认词）后才输出标记
  - 标记必须是回复的最后一行，标记后面不能有任何文字

JSON标记说明（修订版）：
  - host: 纯 IP 或域名，不带端口（必填）
  - cmd: 固定填 "whoami"
  - do_port_scan: 若用户已知端口则 false，否则 true（布尔值）
  - ports: 用户指定的端口列表，如 [82,83]；未指定或要扫描常用端口则填 null
    * 示例：[80] 或 [8080,8081,8082] 或 [22,80,443,3306]
    * 注意：如果用户说"范围 1-100"，应询问用户是要完整端口扫描还是指定具体端口
    * 完整扫描：设置 do_port_scan=true, ports=null
    * 指定端口：请用户列出具体端口号，如"80, 443, 8080"，然后设置 ports=[80,443,8080]
  - port_timeout: 固定填 2（秒）

其他规则：
  - 请用中文回答
  - 仅在授权合法场景下提供帮助，不协助任何非法行为
  - 如果用户没有表达渗透测试意图，正常对话回答网络安全相关问题
  - 注意！如果用户说"端口 82 和 83"，必须填 "ports":[82,83]，不能填 null
  - 【严格规则】参数确认阶段绝对禁止输出任何 ##AUTOTEST## 标记，标记只能在用户明确确认后输出

【测试完成后的回复规则】
当自动化测试完成后（看到 [AI执行完成] 标记），你的回复必须满足以下要求：

只能输出以下内容（3-4 行）：
1. 简要说明测试目标和使用的端口
2. 列出发现的 CVE 和成功状态（哪些端口成功了）
3. 显示成功率统计（例如 2/2 成功）

【绝对禁止】在此阶段输出任何其他内容，包括但不限于：
  ❌ 绝对禁止：修复建议
  ❌ 绝对禁止：升级步骤
  ❌ 绝对禁止：WAF 规则
  ❌ 绝对禁止：安全加固措施
  ❌ 绝对禁止：培训或教学内容
  ❌ 绝对禁止：所有其他内容

触发条件（何时输出建议）：
  仅当用户主动询问以下关键词时才输出建议：
  - "建议"
  - "怎么修复"
  - "如何防护"
  - "防护方案"
  - "修复方案"
  - "加固"
  - "升级"
  - 其他类似询问建议的表述

规则强度：【严格执行】测试完成后绝对不能输出任何建议内容，即使看起来很有帮助也不行"""

    def __init__(self, api_key: str, model: str, messages: list,
                 base_url: str = "https://dashscope.aliyuncs.com/compatible-mode/v1"):
        """
        初始化 Worker。

        Args:
            api_key:   用户填写的千问 API Key
            model:     模型名，如 "qwen-plus" 或 "qwen-turbo"
            messages:  完整对话历史列表（含 system message），格式：
                       [{"role": "system", "content": "..."},
                        {"role": "user", "content": "..."},
                        {"role": "assistant", "content": "..."},
                        ...]
            base_url:  API Base URL（默认为阿里云千问兼容端点）
        """
        super().__init__()
        self.api_key = api_key
        self.model = model
        self.messages = messages        # 外部传入完整历史（GUI 负责维护）
        self.base_url = base_url
        self._stop_flag = False

    def stop(self):
        """请求中止本次流式输出"""
        self._stop_flag = True

    def run(self):
        """
        执行流式 API 调用。

        设计要点：
        - streaming=True，逐 chunk 发射 token_signal
        - 捕获 openai 库未安装 / API 错误两种情况
        - 无论成功与否，最终发射 finished 信号（解锁 GUI 按钮）
        """
        try:
            # 懒导入：避免 openai 未安装时影响整个程序启动
            try:
                from openai import OpenAI
            except ImportError:
                self.error.emit(
                    "openai 库未安装，请运行: pip install openai>=1.0.0"
                )
                self.finished.emit()
                return

            client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )

            # 发起流式请求
            stream = client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                stream=True,
            )

            for chunk in stream:
                # 检查中止标志
                if self._stop_flag:
                    break

                # 安全提取 delta content（处理编码）
                try:
                    delta = chunk.choices[0].delta.content
                    if delta:
                        # 确保 delta 是字符串，并且编码正确
                        if isinstance(delta, bytes):
                            delta = delta.decode('utf-8', errors='replace')
                        elif not isinstance(delta, str):
                            delta = str(delta)
                        self.token_signal.emit(delta)
                except (AttributeError, IndexError):
                    # chunk 结构异常时跳过，不中断流
                    continue
                except UnicodeEncodeError:
                    # 编码错误时跳过该 token，继续处理后续
                    continue

        except Exception as e:
            # 安全地处理异常信息（处理中文字符编码）
            try:
                error_msg = str(e)
            except Exception:
                error_msg = repr(e)
            self.error.emit(error_msg)

        finally:
            # 无论何种结束方式，均发射 finished 以解锁 GUI
            self.finished.emit()
