# -*- coding: utf-8 -*-
"""Generate command - 从HTTP数据包生成Payload模板"""

import os
import sys
import argparse
from . import BaseCommand


class GenerateCommand(BaseCommand):
    """从HTTP数据包生成Payload模板"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加generate命令的参数"""
        parser.add_argument('--packet', help='HTTP数据包字符串')
        parser.add_argument('--packet-file', help='HTTP数据包文件路径')
        parser.add_argument('--cve-id', required=True, help='CVE编号（如: CVE-2024-XXXX）')
        parser.add_argument('--output-dir', help='输出目录（默认: payloads/）')
        parser.add_argument('--save', action='store_true', help='将拆解结果生成payload模板文件')

    def execute(self, args: argparse.Namespace) -> int:
        """执行generate命令"""
        try:
            # 导入必要的模块
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from src.core.packet_generator import generate_from_packet, read_packet_file

            # 读取数据包
            if args.packet:
                packet = args.packet
            elif args.packet_file:
                if not os.path.exists(args.packet_file):
                    print(f"[!] 错误: 文件不存在: {args.packet_file}", file=sys.stderr, flush=True)
                    return 1
                packet = read_packet_file(args.packet_file)
            else:
                print("[!] 错误: 必须提供 --packet 或 --packet-file", file=sys.stderr, flush=True)
                return 1

            result = generate_from_packet(
                packet=packet,
                cve_id=args.cve_id,
                save=getattr(args, "save", False),
                output_dir=args.output_dir
            )

            return 0 if result else 1

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            return 1
