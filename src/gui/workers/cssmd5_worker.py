# -*- coding: utf-8 -*-
"""CSS MD5 Worker - CSS MD5计算工作线程"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class CSSMD5Worker(QThread):
    """CSS MD5计算工作线程"""
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, page_url, timeout):
        super().__init__()
        self.page_url = page_url
        self.timeout = timeout

    def run(self):
        try:
            from fingerprint import get_css_files_md5_from_page

            if get_css_files_md5_from_page is None:
                self.error.emit("CSS MD5功能未加载")
                return

            result = get_css_files_md5_from_page(self.page_url, self.timeout)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))
