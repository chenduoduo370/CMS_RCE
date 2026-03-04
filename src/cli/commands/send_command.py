# -*- coding: utf-8 -*-
"""Send command - 发送Payload到目标"""

import os
import sys
import json
import argparse
from . import BaseCommand


class SendCommand(BaseCommand):
    """发送Payload到目标"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加send命令的参数"""
        parser.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
        parser.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
        parser.add_argument('cmd', nargs='+', help='要执行的命令')
        parser.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒，默认10）')
        parser.add_argument('--debug', action='store_true', help='启用调试模式')
        parser.add_argument('--json-output', action='store_true', help='输出JSON格式结果（用于管道传递）')

    def execute(self, args: argparse.Namespace) -> int:
        """执行send命令"""
        try:
            # 导入PayloadManager
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from src.core.payload_sender import PayloadManager

            manager = PayloadManager(debug=args.debug)
            cmd = ' '.join(args.cmd)
            timeout = args.timeout

            result = manager.send_payload(args.module, args.ip_port, cmd, timeout=timeout)

            if args.json_output:
                # 输出JSON格式结果
                response_data = {
                    "type": "payload_result",
                    "cve": args.module.replace('_', '-'),
                    "target": args.ip_port,
                    "cmd": cmd,
                    "success": bool(result),
                    "response_url": getattr(result, 'url', '') if result else '',
                    "status_code": getattr(result, 'status_code', None) if result else None,
                    "response_text": getattr(result, 'text', '')[:500] if result else ''  # 限制长度
                }
                print(json.dumps(response_data, ensure_ascii=False), flush=True)

            return 0 if result else 1

        except Exception as e:
            if args.json_output:
                # 输出JSON格式错误
                error_data = {
                    "type": "payload_result",
                    "cve": args.module.replace('_', '-'),
                    "target": args.ip_port,
                    "cmd": ' '.join(args.cmd),
                    "success": False,
                    "error": str(e)
                }
                print(json.dumps(error_data, ensure_ascii=False), flush=True)
            else:
                print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
                if args.debug:
                    import traceback
                    traceback.print_exc()
            return 1
