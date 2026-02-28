# -*- coding: utf-8 -*-
"""
AI 管理器 - 集成所有 AI 相关功能

负责：
1. 管理 AI 对话
2. 解析 AI 生成的触发标记
3. 通过 CLI 执行底层功能
4. 记录执行日志
"""

import os
from typing import Callable, Optional, Dict, Tuple
from .console import AIConsole
from .cli_executor import CLIExecutor
from .trigger_handler import TriggerHandler


class AIManager:
    """AI 管理器 - 集成所有 AI 相关功能"""

    def __init__(self, project_root: str, api_key: str, model: str, base_url: str):
        """
        初始化 AI 管理器

        Args:
            project_root: 项目根目录
            api_key: 千问 API Key
            model: 模型名称
            base_url: API 基础 URL
        """
        self.project_root = project_root
        self.console = AIConsole(api_key, model, base_url)
        self.executor = CLIExecutor(project_root)
        self.trigger_handler = TriggerHandler()

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
        self.console.send_message(user_message, on_token, on_finished, on_error)

    def add_ai_response(self, response: str) -> None:
        """将 AI 回复添加到历史记录"""
        self.console.add_ai_response(response)

    def detect_and_execute_trigger(self, response: str,
                                   on_output: Callable[[str], None],
                                   on_finished: Optional[Callable[[], None]] = None) -> Tuple[bool, Optional[str]]:
        """
        检测 AI 回复中的触发标记并执行

        Returns:
            (has_trigger, error_message)
        """
        trigger_type, params = self.trigger_handler.detect_trigger(response)

        if not trigger_type:
            return False, None

        # 验证参数
        is_valid, error_msg = self.trigger_handler.validate_params(trigger_type, params)
        if not is_valid:
            return True, error_msg

        # 构建 CLI 命令
        cmd_list = self._build_cli_command(trigger_type, params)
        if not cmd_list:
            return True, "无法构建 CLI 命令"

        # 执行 CLI 命令
        self.executor.execute(cmd_list, on_output, on_finished)
        return True, None

    def _build_cli_command(self, trigger_type: str, params: Dict) -> Optional[list]:
        """
        根据触发类型和参数构建 CLI 命令

        Returns:
            命令列表或 None
        """
        if trigger_type == 'portscan':
            return self._build_portscan_command(params)
        elif trigger_type == 'fingerprint':
            return self._build_fingerprint_command(params)
        elif trigger_type == 'autotest':
            return self._build_autotest_command(params)
        return None

    def _build_portscan_command(self, params: Dict) -> list:
        """构建端口扫描命令"""
        cmd = ['python', 'poc_tool.py', 'portscan', params['host']]

        if 'ports' in params and params['ports']:
            ports_str = ','.join(map(str, params['ports']))
            cmd.extend(['--ports', ports_str])
        else:
            cmd.append('--common')

        timeout = params.get('timeout', 2)
        cmd.extend(['--timeout', str(timeout)])

        return cmd

    def _build_fingerprint_command(self, params: Dict) -> list:
        """构建指纹识别命令"""
        cmd = ['python', 'poc_tool.py', 'fingerprint', params['host']]

        timeout = params.get('timeout', 3)
        cmd.extend(['--timeout', str(timeout)])

        return cmd

    def _build_autotest_command(self, params: Dict) -> list:
        """构建自动化测试命令"""
        cmd = ['python', 'poc_tool.py', 'auto', params['host']]

        cmd_arg = params.get('cmd', 'whoami')
        cmd.extend(['--cmd', cmd_arg])

        timeout = params.get('port_timeout', 2)
        cmd.extend(['--timeout', str(timeout)])

        if 'ports' in params and params['ports']:
            ports_str = ','.join(map(str, params['ports']))
            cmd.extend(['--ports', ports_str])

        return cmd

    def stop(self) -> None:
        """停止当前 AI 对话"""
        self.console.stop()

    def clear_history(self) -> None:
        """清空对话历史"""
        self.console.clear_history()
