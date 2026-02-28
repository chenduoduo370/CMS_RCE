# -*- coding: utf-8 -*-
"""Fingerprint command - 资源指纹识别"""

import os
import sys
import argparse
from . import BaseCommand


class FingerprintCommand(BaseCommand):
    """资源指纹识别命令"""

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """添加fingerprint命令的参数"""
        parser.add_argument('url', help='目标URL（如: http://192.168.1.1:80/）')
        parser.add_argument('--timeout', type=float, default=3.0, help='超时时间（秒，默认3.0）')

    def execute(self, args: argparse.Namespace) -> int:
        """执行fingerprint命令"""
        try:
            # 导入指纹识别模块
            sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            from fingerprint import get_css_files_md5_from_page

            url = args.url
            timeout = args.timeout

            print(f"\n{'='*60}", flush=True)
            print(f"资源指纹识别 - {url}", flush=True)
            print(f"{'='*60}\n", flush=True)

            # 执行指纹识别
            print("[*] 正在进行指纹识别...", flush=True)
            css_md5_dict = get_css_files_md5_from_page(url, timeout)

            if not css_md5_dict:
                print("\n[!] 未找到CSS文件或指纹识别失败", flush=True)
                return 1

            # 显示结果
            print(f"\n[+] 识别到 {len(css_md5_dict)} 个资源:", flush=True)
            for css_url, info in css_md5_dict.items():
                if isinstance(info, tuple):
                    md5_hash, cve_id = info
                    cve_info = f" → 匹配 {cve_id}" if cve_id else ""
                    print(f"    - {css_url}", flush=True)
                    print(f"      MD5: {md5_hash}{cve_info}", flush=True)
                else:
                    print(f"    - {css_url} ({info})", flush=True)

            # 统计匹配到的 CVE
            matched_cves = set()
            for css_url, info in css_md5_dict.items():
                if isinstance(info, tuple):
                    _, cve_id = info
                    if cve_id:
                        matched_cves.add(cve_id)

            if matched_cves:
                print(f"\n[+] 匹配到 {len(matched_cves)} 个CVE:", flush=True)
                for cve in matched_cves:
                    print(f"    - {cve}", flush=True)
            else:
                print("\n[!] 未匹配到任何已知CVE", flush=True)

            print(f"\n{'='*60}\n", flush=True)

            return 0

        except Exception as e:
            print(f"[!] 错误: {e}", file=sys.stderr, flush=True)
            return 1
