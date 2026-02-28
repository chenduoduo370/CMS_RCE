# -*- coding: utf-8 -*-
"""
触发器处理器 - 解析 AI 生成的标记并触发 CLI 命令

AI 生成特殊标记（##PORTSCAN##, ##FINGERPRINT##, ##AUTOTEST##），
此模块负责解析这些标记并调用相应的 CLI 命令。
"""

import json
import re
from typing import Dict, Optional, Tuple


class TriggerHandler:
    """处理 AI 生成的触发标记"""

    # 标记模式
    PORTSCAN_PATTERN = r'##PORTSCAN##(\{.+?\})##END##'
    FINGERPRINT_PATTERN = r'##FINGERPRINT##(\{.+?\})##END##'
    AUTOTEST_PATTERN = r'##AUTOTEST##(\{.+?\})##END##'

    @staticmethod
    def parse_portscan(response: str) -> Optional[Dict]:
        """
        解析端口扫描标记

        Returns:
            {"host": "...", "ports": [...], "timeout": 2} 或 None
        """
        match = re.search(TriggerHandler.PORTSCAN_PATTERN, response, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def parse_fingerprint(response: str) -> Optional[Dict]:
        """
        解析指纹识别标记

        Returns:
            {"host": "...", "timeout": 3} 或 None
        """
        match = re.search(TriggerHandler.FINGERPRINT_PATTERN, response, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def parse_autotest(response: str) -> Optional[Dict]:
        """
        解析自动化测试标记

        Returns:
            {"host": "...", "cmd": "whoami", "do_port_scan": false, "ports": [...], "port_timeout": 2} 或 None
        """
        match = re.search(TriggerHandler.AUTOTEST_PATTERN, response, re.DOTALL)
        if not match:
            return None

        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def detect_trigger(response: str) -> Tuple[Optional[str], Optional[Dict]]:
        """
        检测 AI 回复中的触发标记

        Returns:
            (trigger_type, params) 其中 trigger_type 为 'portscan', 'fingerprint', 'autotest' 或 None
        """
        # 检测顺序很重要，因为标记可能嵌套
        if '##AUTOTEST##' in response:
            params = TriggerHandler.parse_autotest(response)
            if params:
                return 'autotest', params

        if '##FINGERPRINT##' in response:
            params = TriggerHandler.parse_fingerprint(response)
            if params:
                return 'fingerprint', params

        if '##PORTSCAN##' in response:
            params = TriggerHandler.parse_portscan(response)
            if params:
                return 'portscan', params

        return None, None

    @staticmethod
    def validate_params(trigger_type: str, params: Dict) -> Tuple[bool, Optional[str]]:
        """
        验证参数的有效性

        Returns:
            (is_valid, error_message)
        """
        if not params:
            return False, "参数为空"

        # 所有触发器都需要 host 参数
        host = params.get("host", "").strip()
        if not host:
            return False, "缺少目标地址 (host)"

        if trigger_type == 'portscan':
            # 端口扫描可选参数：ports, timeout
            timeout = params.get("timeout", 2)
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                return False, "超时时间必须为正数"

        elif trigger_type == 'fingerprint':
            # 指纹识别可选参数：timeout
            timeout = params.get("timeout", 3)
            if not isinstance(timeout, (int, float)) or timeout <= 0:
                return False, "超时时间必须为正数"

        elif trigger_type == 'autotest':
            # 自动化测试必需参数：cmd, do_port_scan, port_timeout
            cmd = params.get("cmd", "").strip()
            if not cmd:
                return False, "缺少执行命令 (cmd)"

            do_port_scan = params.get("do_port_scan")
            if not isinstance(do_port_scan, bool):
                return False, "do_port_scan 必须为布尔值"

            port_timeout = params.get("port_timeout", 2)
            if not isinstance(port_timeout, (int, float)) or port_timeout <= 0:
                return False, "端口超时时间必须为正数"

        return True, None
