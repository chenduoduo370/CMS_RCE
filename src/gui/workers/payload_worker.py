# -*- coding: utf-8 -*-
"""Payload Worker - Payload发送工作线程"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class PayloadWorker(QThread):
    """Payload 发送工作线程"""
    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, manager, module_name, ip_port, cmd, timeout=10):
        super().__init__()
        self.manager = manager
        self.module_name = module_name
        self.ip_port = ip_port
        self.cmd = cmd
        self.timeout = timeout

    def run(self):
        try:
            result = self.manager.send_payload(
                self.module_name,
                self.ip_port,
                self.cmd,
                self.timeout
            )
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
