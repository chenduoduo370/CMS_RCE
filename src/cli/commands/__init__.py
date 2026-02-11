# -*- coding: utf-8 -*-
"""CLI commands package"""

from abc import ABC, abstractmethod
import argparse
from typing import Optional


class BaseCommand(ABC):
    """命令基类"""

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """
        添加命令参数

        Args:
            parser: argparse子解析器
        """
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> int:
        """
        执行命令

        Args:
            args: 解析后的命令行参数

        Returns:
            int: 退出码，0表示成功，非0表示失败
        """
        pass
