#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Payload 渗透测试工具 - 命令行入口
向后兼容的入口点，使用重构后的CLI模块
"""

import sys
import os

# 添加项目根目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# 导入新的CLI主入口
try:
    from src.cli.main import main
except ImportError:
    # 如果新模块不可用，提示用户
    print("[!] 错误: 无法导入CLI模块", file=sys.stderr)
    print("[!] 请确保src/cli目录存在且包含必要的文件", file=sys.stderr)
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main())
