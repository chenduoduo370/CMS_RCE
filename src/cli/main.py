# -*- coding: utf-8 -*-
"""
CLI主入口模块
使用命令注册模式，简化主函数逻辑
"""

import sys
import argparse
from .commands.show_command import ShowCommand
from .commands.send_command import SendCommand
from .commands.list_command import ListCommand
from .commands.generate_command import GenerateCommand
from .commands.portscan_command import PortscanCommand
from .commands.auto_command import AutoCommand


def main():
    """CLI主入口函数"""
    parser = argparse.ArgumentParser(
        prog='poc_tool',
        description='CVE Payload 渗透测试工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s list
  %(prog)s show CVE_2019_6340 192.168.1.1:80 id
  %(prog)s send CVE_2019_6340 192.168.1.1:80 whoami
  %(prog)s generate --packet-file packet.txt --cve-id CVE-2024-XXXX --save
  %(prog)s auto http://192.168.1.1:80/ --cmd "id"
  %(prog)s portscan 192.168.1.1 --common
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # 注册所有命令
    commands = {
        'show': ShowCommand(),
        'send': SendCommand(),
        'list': ListCommand(),
        'generate': GenerateCommand(),
        'portscan': PortscanCommand(),
        'auto': AutoCommand(),
    }

    # 为每个命令创建子解析器并添加参数
    for name, cmd in commands.items():
        cmd_parser = subparsers.add_parser(name, help=cmd.__doc__)
        cmd.add_arguments(cmd_parser)

    # 解析参数
    args = parser.parse_args()

    # 如果没有指定命令，显示帮助信息
    if not args.command:
        parser.print_help()
        return 1

    # 执行对应的命令
    try:
        return commands[args.command].execute(args)
    except KeyboardInterrupt:
        print("\n[!] 用户中断", file=sys.stderr, flush=True)
        return 130
    except Exception as e:
        print(f"[!] 未预期的错误: {e}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
