# -*- coding: utf-8 -*-
"""
AI 控制台 - 千问 AI 对话和参数收集

负责与用户进行自然语言交互，收集渗透测试参数，
然后生成特殊标记让 GUI 通过 CLI 命令执行。
"""

from typing import Optional, Callable
from src.gui.workers import QianwenWorker


class AIConsole:
    """AI 控制台 - 管理 AI 对话和参数收集"""

    def __init__(self, api_key: str, model: str, base_url: str):
        """
        初始化 AI 控制台

        Args:
            api_key: 千问 API Key
            model: 模型名称
            base_url: API 基础 URL
        """
        self.api_key = api_key
        self.model = model
        self.base_url = base_url
        self.history = []
        self.worker = None

    def send_message(self, user_message: str, on_token: Callable[[str], None],
                     on_finished: Callable[[], None],
                     on_error: Callable[[str], None]) -> None:
        """
        发送消息给 AI

        Args:
            user_message: 用户消息
            on_token: 流式 token 回调
            on_finished: 完成回调
            on_error: 错误回调
        """
        # 初始化历史记录
        if not self.history:
            self.history.append({
                "role": "system",
                "content": QianwenWorker.SYSTEM_PROMPT
            })

        # 添加用户消息
        self.history.append({
            "role": "user",
            "content": user_message
        })

        # 创建 Worker
        self.worker = QianwenWorker(
            api_key=self.api_key,
            model=self.model,
            messages=list(self.history),
            base_url=self.base_url
        )

        self.worker.token_signal.connect(on_token)
        self.worker.finished.connect(on_finished)
        self.worker.error.connect(on_error)
        self.worker.start()

    def add_ai_response(self, response: str) -> None:
        """
        将 AI 回复添加到历史记录

        Args:
            response: AI 回复内容
        """
        self.history.append({
            "role": "assistant",
            "content": response
        })

    def stop(self) -> None:
        """停止当前 AI 对话"""
        if self.worker and self.worker.isRunning():
            self.worker.stop()

    def clear_history(self) -> None:
        """清空对话历史"""
        self.history = []
