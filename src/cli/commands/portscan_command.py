# -*- coding: utf-8 -*-
"""Portscan command - 端口扫描"""

import os
import sys
import argparse
from . import BaseCommand


class PortscanCommand(BaseCommand):
    """端口扫描命令"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加portscan命令的参数"""
        parser.add_argument('host', help='目标主机IP或域名')
        parser.add_argument('--ports', help='要扫描的端口列表（逗号分隔，如: 80,443,8080）')
        parser.add_argument('--range', help='端口范围（如: 1-1000）')
        parser.add_argument('--common', action='store_true', help='扫描常见端口')
        parser.add_argument('--timeout', type=float, default=2.0, help='超时时间（秒，默认2.0）')

    def execute(self, args: argparse.Namespace) -> int:
        """执行portscan命令"""
        try:
            # 导入端口扫描模块
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from src.core.port_scanner import scan_ports, scan_common_ports, COMMON_PORTS

            host = args.host
            timeout = args.timeout

            print(f"\n{'='*60}", flush=True)
            print(f"端口扫描 - {host}", flush=True)
            print(f"{'='*60}\n", flush=True)

            # 确定要扫描的端口
            if args.ports:
                # 扫描指定端口
                ports = [int(p.strip()) for p in args.ports.split(',')]
                print(f"[*] 扫描指定端口: {', '.join(map(str, ports))}", flush=True)
                open_ports = scan_ports(host, ports, timeout=timeout)
            elif args.range:
                # 扫描端口范围
                start, end = map(int, args.range.split('-'))
                ports = list(range(start, end + 1))
                print(f"[*] 扫描端口范围: {start}-{end}", flush=True)
                open_ports = scan_ports(host, ports, timeout=timeout)
            elif args.common:
                # 扫描常见端口
                print(f"[*] 扫描常见端口 (共 {len(COMMON_PORTS)} 个)", flush=True)
                open_ports = scan_common_ports(host, timeout=timeout)
            else:
                # 默认扫描常见端口
                print(f"[*] 扫描常见端口 (共 {len(COMMON_PORTS)} 个)", flush=True)
                open_ports = scan_common_ports(host, timeout=timeout)

            # 显示结果
            if open_ports:
                print(f"\n[+] 发现 {len(open_ports)} 个开放端口:", flush=True)
                for port, service in open_ports:
                    service_name = f" ({service})" if service else ""
                    print(f"    - {port}{service_name}", flush=True)
            else:
                print("\n[!] 未发现开放端口", flush=True)

            print(f"\n{'='*60}\n", flush=True)

            return 0

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            return 1
