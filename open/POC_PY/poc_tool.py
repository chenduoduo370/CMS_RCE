#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Payload工具 - 统一的命令行工具
整合了payload生成、测试、发送和脚本生成功能
"""

import sys
import os
import json
import argparse
from typing import Optional

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# 强制刷新输出缓冲区
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

# 导入拆分后的模块
from payload_sender import PayloadManager, list_payloads
from packet_generator import generate_from_packet, read_packet_file

try:
    from fingerprint import get_file_md5, get_css_files_md5_from_page
except ImportError:
    get_file_md5 = None
    get_css_files_md5_from_page = None

try:
    from fingerprint_cve_mapping import get_manager
except ImportError:
    get_manager = None
 


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='CVE Payload工具 - 统一的命令行工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 显示payload（不发送）
  %(prog)s show CVE_2019_6340 192.168.1.1:80 "id"
  
  # 发送payload
  %(prog)s send CVE_2019_6340 192.168.1.1:80 "id"
  
  # 列出所有payload
  %(prog)s list
  
  # 从HTTP数据包生成CVE脚本
  %(prog)s generate --packet-file packet.txt --cve-id CVE-2024-XXXX
  
  # 计算指定文件的MD5值（通过URL）
  %(prog)s md5 file http://192.168.1.1:80/core/CHANGELOG.txt
  
  # 访问页面，提取CSS文件并计算MD5值
  %(prog)s md5 css http://192.168.1.1:80/
  
  # 管理指纹-CVE映射
  %(prog)s fingerprint add abc123def456 --cve CVE-2024-XXXX --description "示例描述"
  %(prog)s fingerprint list
  %(prog)s fingerprint get abc123def456
  %(prog)s fingerprint remove abc123def456
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    # show命令 - 显示payload
    parser_show = subparsers.add_parser('show', help='显示payload（不发送）')
    parser_show.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
    parser_show.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
    parser_show.add_argument('cmd', nargs='+', help='要执行的命令')
    parser_show.add_argument('--json', action='store_true', help='同时显示JSON格式')
    parser_show.add_argument('--debug', action='store_true', help='启用调试模式')
    
    # send命令 - 发送payload
    parser_send = subparsers.add_parser('send', help='发送payload到目标')
    parser_send.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
    parser_send.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
    parser_send.add_argument('cmd', nargs='+', help='要执行的命令')
    parser_send.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒，默认10）')
    parser_send.add_argument('--debug', action='store_true', help='启用调试模式')
    
    # list命令 - 列出所有payload
    parser_list = subparsers.add_parser('list', help='列出所有可用的payload模块')
    
    # generate命令 - 从HTTP数据包拆解并可生成payload模板
    parser_gen = subparsers.add_parser('generate', help='从HTTP数据包拆解并可生成payload模板')
    parser_gen.add_argument('--packet', help='HTTP数据包字符串')
    parser_gen.add_argument('--packet-file', help='HTTP数据包文件路径')
    parser_gen.add_argument('--cve-id', required=True, help='CVE编号（如: CVE-2024-XXXX）')
    parser_gen.add_argument('--output-dir', help='输出目录（默认: payloads/）')
    parser_gen.add_argument('--save', action='store_true', help='将拆解结果生成payload模板文件')
    
    # md5命令 - 通过URL计算指定文件的MD5值
    parser_md5 = subparsers.add_parser('md5', help='通过URL下载文件并计算MD5哈希值')
    md5_subparsers = parser_md5.add_subparsers(dest='md5_subcommand', help='MD5子命令')
    
    # md5 file - 计算单个文件的MD5
    parser_md5_file = md5_subparsers.add_parser('file', help='计算指定文件的MD5值')
    parser_md5_file.add_argument('url', help='文件的完整URL（如: http://192.168.1.1:80/core/CHANGELOG.txt）')
    parser_md5_file.add_argument('--timeout', type=float, default=3.0, help='请求超时时间（秒，默认3.0）')
    
    # md5 css - 从页面提取CSS文件并计算MD5
    parser_md5_css = md5_subparsers.add_parser('css', help='访问页面，提取CSS文件并计算MD5值')
    parser_md5_css.add_argument('url', help='页面URL（如: http://192.168.1.1:80/）')
    parser_md5_css.add_argument('--timeout', type=float, default=3.0, help='请求超时时间（秒，默认3.0）')
    
    # fingerprint命令 - 管理指纹-CVE映射
    parser_fp = subparsers.add_parser('fingerprint', help='管理指纹-CVE映射关系')
    fp_subparsers = parser_fp.add_subparsers(dest='fp_subcommand', help='指纹管理子命令')
    
    # fingerprint add - 添加指纹-CVE映射
    parser_fp_add = fp_subparsers.add_parser('add', help='添加或更新指纹-CVE映射')
    parser_fp_add.add_argument('fingerprint', help='指纹（如MD5值）')
    parser_fp_add.add_argument('--cve', help='CVE编号（可选，留空表示无CVE）')
    parser_fp_add.add_argument('--description', help='描述信息（可选）')
    
    # fingerprint remove - 删除指纹-CVE映射
    parser_fp_remove = fp_subparsers.add_parser('remove', help='删除指纹-CVE映射')
    parser_fp_remove.add_argument('fingerprint', help='指纹（如MD5值）')
    
    # fingerprint list - 列出所有映射
    parser_fp_list = fp_subparsers.add_parser('list', help='列出所有指纹-CVE映射')
    parser_fp_list.add_argument('--cve', help='按CVE编号筛选')
    
    # fingerprint get - 查询指定指纹的CVE
    parser_fp_get = fp_subparsers.add_parser('get', help='查询指定指纹对应的CVE')
    parser_fp_get.add_argument('fingerprint', help='指纹（如MD5值）')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)

    manager = PayloadManager(debug=args.debug if hasattr(args, 'debug') else False)
    
    if args.command == 'show':
        cmd = ' '.join(args.cmd)
        result = manager.show_payload(args.module, args.ip_port, cmd, show_json=args.json)
        sys.exit(0 if result else 1)
    
    elif args.command == 'send':
        cmd = ' '.join(args.cmd)
        timeout = args.timeout
        result = manager.send_payload(args.module, args.ip_port, cmd, timeout=timeout)
        sys.exit(0 if result else 1)
    
    elif args.command == 'list':
        list_payloads()
        sys.exit(0)
    
    elif args.command == 'generate':
        # 读取数据包
        if args.packet:
            packet = args.packet
        elif args.packet_file:
            if not os.path.exists(args.packet_file):
                print(f"[!] 错误: 文件不存在: {args.packet_file}", file=sys.stderr, flush=True)
                sys.exit(1)
            packet = read_packet_file(args.packet_file)
        else:
            print("[!] 错误: 必须提供 --packet 或 --packet-file", file=sys.stderr, flush=True)
            sys.exit(1)
        
        result = generate_from_packet(
            packet=packet,
            cve_id=args.cve_id,
            save=getattr(args, "save", False),
            output_dir=args.output_dir
        )
        sys.exit(0 if result else 1)
    
    elif args.command == 'md5':
        if get_file_md5 is None or get_css_files_md5_from_page is None:
            print("[!] 指纹模块未加载，无法执行 md5 命令", file=sys.stderr, flush=True)
            sys.exit(1)
        
        # 检查是否有子命令
        if not hasattr(args, 'md5_subcommand') or args.md5_subcommand is None:
            # 如果没有子命令，默认使用file命令（向后兼容）
            args.md5_subcommand = 'file'
        
        if args.md5_subcommand == 'file':
            url = args.url
            timeout = args.timeout
            
            print(f"\n{'='*60}", flush=True)
            print("计算文件 MD5 哈希值", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"文件 URL: {url}", flush=True)
            print(f"{'='*60}\n", flush=True)
            
            print(f"[*] 正在下载文件并计算 MD5...", flush=True)
            md5_hash = get_file_md5(url, timeout)
            
            if md5_hash:
                print(f"\n[+] 文件 MD5 哈希值: {md5_hash}", flush=True)
                print(f"文件 URL: {url}", flush=True)
                print("=" * 60, flush=True)
                sys.exit(0)
            else:
                print(f"\n[!] 无法下载文件或计算 MD5 失败", file=sys.stderr, flush=True)
                print(f"    - 请检查 URL 是否正确", flush=True)
                print(f"    - 请检查文件是否可以访问", flush=True)
                print(f"    - 请检查网络连接是否正常", flush=True)
                sys.exit(1)
        
        elif args.md5_subcommand == 'css':
            url = args.url
            timeout = args.timeout
            
            print(f"\n{'='*60}", flush=True)
            print("提取页面CSS文件并计算MD5哈希值，并匹配CVE", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"页面 URL: {url}", flush=True)
            print(f"{'='*60}\n", flush=True)
            
            print(f"[*] 正在访问页面并提取CSS文件链接...", flush=True)
            css_md5_dict = get_css_files_md5_from_page(url, timeout)
            
            if css_md5_dict:
                print(f"[+] 找到 {len(css_md5_dict)} 个CSS文件:", flush=True)
                success_count = 0
                matched_cve = 0
                matched_cve_set = set()
                for idx, (css_url, info) in enumerate(css_md5_dict.items(), 1):
                    # 兼容返回值：可能是 md5 字符串或 (md5, cve)
                    if isinstance(info, tuple):
                        md5_hash, cve_id = info
                    else:
                        md5_hash, cve_id = info, None
                    
                    print(f"\n[{idx}] URL: {css_url}", flush=True)
                    if md5_hash:
                        print(f"     MD5: {md5_hash}", flush=True)
                        if cve_id:
                            print(f"     CVE: {cve_id}", flush=True)
                            matched_cve += 1
                            matched_cve_set.add(cve_id)
                        else:
                            print("     CVE: (未匹配)", flush=True)
                        success_count += 1
                    else:
                        print("     MD5: (下载失败)", flush=True)
                        print("     CVE: -", flush=True)
                
                print(f"\n{'='*60}", flush=True)
                print(f"成功: {success_count}/{len(css_md5_dict)}", flush=True)
                if matched_cve_set:
                    print(f"匹配到的 CVE 列表: {', '.join(sorted(matched_cve_set))}", flush=True)
                sys.exit(0 if success_count > 0 else 1)
            else:
                print(f"\n[!] 未找到CSS文件或访问页面失败", file=sys.stderr, flush=True)
                print(f"    - 请检查 URL 是否正确", flush=True)
                print(f"    - 请检查页面是否可以访问", flush=True)
                print(f"    - 请检查网络连接是否正常", flush=True)
            sys.exit(1)
    
    elif args.command == 'fingerprint':
        if get_manager is None:
            print("[!] 指纹-CVE映射模块未加载，无法执行 fingerprint 命令", file=sys.stderr, flush=True)
            sys.exit(1)
        
        manager = get_manager()
        
        if not hasattr(args, 'fp_subcommand') or args.fp_subcommand is None:
            parser_fp.print_help()
            sys.exit(1)
        
        if args.fp_subcommand == 'add':
            fingerprint = args.fingerprint.strip()
            cve_id = args.cve.strip() if args.cve else None
            description = args.description.strip() if args.description else None
            
            if not fingerprint:
                print("[!] 错误: 指纹不能为空", file=sys.stderr, flush=True)
                sys.exit(1)
            
            if manager.add_mapping(fingerprint, cve_id, description):
                print(f"[+] 成功添加映射: {fingerprint} -> {cve_id or '(无CVE)'}", flush=True)
                if description:
                    print(f"    描述: {description}", flush=True)
                sys.exit(0)
            else:
                print("[!] 添加映射失败", file=sys.stderr, flush=True)
                sys.exit(1)
        
        elif args.fp_subcommand == 'remove':
            fingerprint = args.fingerprint.strip()
            
            if manager.remove_mapping(fingerprint):
                print(f"[+] 成功删除映射: {fingerprint}", flush=True)
                sys.exit(0)
            else:
                print(f"[!] 删除失败: 未找到指纹 {fingerprint}", file=sys.stderr, flush=True)
                sys.exit(1)
        
        elif args.fp_subcommand == 'list':
            print(f"\n{'='*60}", flush=True)
            print("指纹-CVE映射列表", flush=True)
            print(f"{'='*60}", flush=True)
            
            if args.cve:
                mappings = manager.search_by_cve(args.cve)
                print(f"按CVE筛选: {args.cve}\n", flush=True)
            else:
                mappings = manager.get_all_mappings()
            
            if not mappings:
                print("[!] 未找到任何映射", flush=True)
            else:
                for i, mapping in enumerate(mappings, 1):
                    print(f"{i}. 指纹: {mapping.fingerprint}", flush=True)
                    print(f"   CVE: {mapping.cve_id or '(无CVE)'}", flush=True)
                    if mapping.description:
                        print(f"   描述: {mapping.description}", flush=True)
                    print("", flush=True)
            
            print(f"共 {len(mappings)} 条映射", flush=True)
            print("=" * 60, flush=True)
            sys.exit(0)
        
        elif args.fp_subcommand == 'get':
            fingerprint = args.fingerprint.strip()
            mapping = manager.get_mapping(fingerprint)
            
            if mapping:
                print(f"\n{'='*60}", flush=True)
                print("指纹-CVE映射信息", flush=True)
                print(f"{'='*60}", flush=True)
                print(f"指纹: {mapping.fingerprint}", flush=True)
                print(f"CVE: {mapping.cve_id or '(无CVE)'}", flush=True)
                if mapping.description:
                    print(f"描述: {mapping.description}", flush=True)
                print("=" * 60, flush=True)
                sys.exit(0)
            else:
                print(f"[!] 未找到指纹 {fingerprint} 的映射", file=sys.stderr, flush=True)
                sys.exit(1)


if __name__ == "__main__":
    main()

