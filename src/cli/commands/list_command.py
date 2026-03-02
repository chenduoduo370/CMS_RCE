# -*- coding: utf-8 -*-
"""List command - 列出所有可用的Payload模块"""

import os
import sys
import argparse
from . import BaseCommand


class ListCommand(BaseCommand):
    """列出所有可用的Payload模块"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """list命令不需要额外参数"""
        pass

    def execute(self, args: argparse.Namespace) -> int:
        """执行list命令"""
        try:
            # 导入PayloadManager
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from src.core.payload_sender import PayloadManager

            manager = PayloadManager(debug=False)
            payloads = manager.list_payloads()

            if not payloads:
                print("[!] 未找到任何Payload模块", flush=True)
                return 1

            print(f"\n{'='*60}", flush=True)
            print(f"可用的Payload模块 (共 {len(payloads)} 个)", flush=True)
            print(f"{'='*60}\n", flush=True)

            for idx, payload_name in enumerate(payloads, 1):
                print(f"[{idx}] {payload_name}", flush=True)

            print(f"\n{'='*60}", flush=True)
            print("使用方法:", flush=True)
            print("  python poc_tool.py show <模块名> <IP:端口> <命令>", flush=True)
            print("  python poc_tool.py send <模块名> <IP:端口> <命令>", flush=True)
            print(f"{'='*60}\n", flush=True)

            return 0

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            return 1
