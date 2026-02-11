# -*- coding: utf-8 -*-
"""Port Scan Worker - 端口扫描工作线程"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class PortScanWorker(QThread):
    """端口扫描工作线程"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, host: str, ports: list = None, timeout: float = 2.0, max_workers: int = 50):
        super().__init__()
        self.host = host
        self.ports = ports
        self.timeout = timeout
        self.max_workers = max_workers

    def run(self):
        try:
            from port_scanner import scan_ports

            if scan_ports is None:
                self.error.emit("端口扫描模块未加载")
                return

            results = scan_ports(self.host, self.ports, timeout=self.timeout, max_workers=self.max_workers)
            self.finished.emit(results)
        except Exception as e:
            self.error.emit(str(e))
