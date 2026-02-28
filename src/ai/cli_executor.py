# -*- coding: utf-8 -*-
"""
CLI 执行器 - 通过子进程执行 CLI 命令

AI 通过此模块执行所有底层功能，确保 AI 与底层代码完全隔离。
"""

import subprocess
import threading
import queue
from typing import Callable, List, Optional


class CLIExecutor:
    """通过 CLI 命令执行功能的执行器"""

    def __init__(self, project_root: str):
        """
        初始化 CLI 执行器

        Args:
            project_root: 项目根目录路径
        """
        self.project_root = project_root
        self._output_queue = None
        self._cli_thread = None

    def execute(self, cmd_list: List[str], on_output: Callable[[str], None],
                on_finished: Optional[Callable[[], None]] = None) -> None:
        """
        执行 CLI 命令

        Args:
            cmd_list: 命令列表，如 ['python', 'poc_tool.py', 'portscan', '192.168.1.1']
            on_output: 输出回调函数，接收每行输出
            on_finished: 完成回调函数（可选）
        """
        self._output_queue = queue.Queue()

        def run_command():
            """在后台线程中执行命令"""
            try:
                process = subprocess.Popen(
                    cmd_list,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    cwd=self.project_root
                )

                # 实时读取输出
                for line in process.stdout:
                    self._output_queue.put(line)

                process.wait()
                self._output_queue.put(None)  # 标记完成

            except Exception as e:
                self._output_queue.put(f"[!] 命令执行错误: {e}\n")
                self._output_queue.put(None)

        def read_output():
            """在主线程中读取输出"""
            while True:
                try:
                    line = self._output_queue.get(timeout=0.1)
                    if line is None:
                        # 执行完成
                        if on_finished:
                            on_finished()
                        break
                    # 调用输出回调
                    on_output(line)
                except queue.Empty:
                    continue

        # 启动后台线程执行命令
        self._cli_thread = threading.Thread(target=run_command, daemon=True)
        self._cli_thread.start()

        # 启动主线程读取输出
        read_thread = threading.Thread(target=read_output, daemon=True)
        read_thread.start()
