# -*- coding: utf-8 -*-
"""Generate Worker - 数据包生成工作线程"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class GenerateWorker(QThread):
    """数据包生成工作线程"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, packet, cve_id, save, output_dir):
        super().__init__()
        self.packet = packet
        self.cve_id = cve_id
        self.save = save
        self.output_dir = output_dir

    def run(self):
        try:
            from src.core.packet_generator import generate_from_packet

            result = generate_from_packet(
                packet=self.packet,
                cve_id=self.cve_id,
                save=self.save,
                output_dir=self.output_dir
            )
            self.finished.emit(result if result else {})
        except Exception as e:
            self.error.emit(str(e))
