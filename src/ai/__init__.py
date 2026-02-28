# -*- coding: utf-8 -*-
"""
AI 模块 - 千问 AI 对话和 CLI 命令执行

AI 通过自然语言与用户交互，收集参数，然后通过 CLI 命令调用底层功能。
AI 与底层代码完全隔离，只能通过预定义的命令行接口操作。
"""

from .console import AIConsole
from .cli_executor import CLIExecutor
from .trigger_handler import TriggerHandler
from .manager import AIManager

__all__ = ['AIConsole', 'CLIExecutor', 'TriggerHandler', 'AIManager']
