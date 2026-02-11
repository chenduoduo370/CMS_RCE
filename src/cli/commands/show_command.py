# -*- coding: utf-8 -*-
"""Show command - 显示Payload内容（不发送）"""

import os
import sys
import argparse
from . import BaseCommand


class ShowCommand(BaseCommand):
    """显示Payload内容（不发送）"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加show命令的参数"""
        parser.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
        parser.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
        parser.add_argument('cmd', nargs='+', help='要执行的命令')
        parser.add_argument('--json', action='store_true', help='同时显示JSON格式')
        parser.add_argument('--debug', action='store_true', help='启用调试模式')

    def execute(self, args: argparse.Namespace) -> int:
        """执行show命令"""
        try:
            # 导入PayloadManager
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            from payload_sender import PayloadManager

            manager = PayloadManager(debug=args.debug)
            cmd = ' '.join(args.cmd)

            result = manager.show_payload(args.module, args.ip_port, cmd, show_json=args.json)

            return 0 if result else 1

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            if args.debug:
                import traceback
                traceback.print_exc()
            return 1
