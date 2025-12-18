#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Payload工具 - 图形化界面
基于 PyQt5 的 GUI 界面
"""

import sys
import os
from pathlib import Path

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                                 QHBoxLayout, QTabWidget, QLabel, QLineEdit,
                                 QPushButton, QTextEdit, QFileDialog, QMessageBox,
                                 QComboBox, QSpinBox, QGroupBox, QFormLayout,
                                 QProgressBar, QListWidget, QSplitter, QTableWidget,
                                 QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QTextCursor
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False
    print("[!] 错误: PyQt5 未安装")
    print("请安装: pip install PyQt5")
    sys.exit(1)

# 导入核心模块（已拆分）
from payload_sender import PayloadManager, list_payloads
from packet_generator import generate_from_packet, read_packet_file

try:
    # CSS MD5计算功能
    from fingerprint import get_file_md5, get_css_files_md5_from_page
except ImportError:
    get_file_md5 = None
    get_css_files_md5_from_page = None

try:
    # 指纹-CVE映射管理
    from fingerprint_cve_mapping import get_manager, FingerprintCVEMapping
except ImportError:
    get_manager = None
    FingerprintCVEMapping = None


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
            result = generate_from_packet(
                packet=self.packet,
                cve_id=self.cve_id,
                save=self.save,
                output_dir=self.output_dir
            )
            self.finished.emit(result if result else {})
        except Exception as e:
            self.error.emit(str(e))


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
            if get_css_files_md5_from_page is None:
                self.error.emit("CSS MD5功能未加载")
                return
            
            result = get_css_files_md5_from_page(self.page_url, self.timeout)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.manager = PayloadManager(debug=False)
        self.init_ui()
    
    def init_ui(self):
        """初始化界面"""
        self.setWindowTitle("CVE Payload 工具 - GUI")
        self.setGeometry(100, 100, 1200, 800)
        
        # 创建标签页
        tabs = QTabWidget()
        
        # Payload 标签页
        payload_tab = self.create_payload_tab()
        tabs.addTab(payload_tab, "Payload 操作")
        
        # 数据包生成标签页
        generate_tab = self.create_generate_tab()
        tabs.addTab(generate_tab, "数据包生成")
        
        # Payload 列表标签页
        list_tab = self.create_list_tab()
        tabs.addTab(list_tab, "Payload 列表")
        
        # CSS MD5 标签页
        css_md5_tab = self.create_css_md5_tab()
        tabs.addTab(css_md5_tab, "CSS MD5 计算")
        
        # 指纹-CVE映射管理标签页
        if get_manager is not None:
            mapping_tab = self.create_fingerprint_tab()
            tabs.addTab(mapping_tab, "指纹-CVE映射")
        
        self.setCentralWidget(tabs)
    
    def create_payload_tab(self):
        """创建 Payload 操作标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("参数设置")
        input_layout = QFormLayout()
        
        # Payload 模块选择
        self.module_combo = QComboBox()
        self.module_combo.setEditable(True)
        self.module_combo.setMinimumWidth(300)
        self.refresh_payload_list()
        input_layout.addRow("Payload 模块:", self.module_combo)
        
        # 目标地址
        self.ip_port_input = QLineEdit()
        self.ip_port_input.setPlaceholderText("例如: 192.168.1.1:80")
        input_layout.addRow("目标地址:", self.ip_port_input)
        
        # 命令
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("例如: id 或 whoami")
        input_layout.addRow("执行命令:", self.cmd_input)
        
        # 超时时间
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 300)
        self.timeout_spin.setValue(10)
        input_layout.addRow("超时时间(秒):", self.timeout_spin)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.show_btn = QPushButton("显示 Payload")
        self.show_btn.clicked.connect(self.show_payload)
        button_layout.addWidget(self.show_btn)
        
        self.send_btn = QPushButton("发送 Payload")
        self.send_btn.clicked.connect(self.send_payload)
        button_layout.addWidget(self.send_btn)

        self.refresh_btn = QPushButton("刷新列表")
        self.refresh_btn.clicked.connect(self.refresh_payload_list)
        button_layout.addWidget(self.refresh_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 结果显示区域
        result_group = QGroupBox("结果显示")
        result_layout = QVBoxLayout()
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.result_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        widget.setLayout(layout)
        return widget

    def create_generate_tab(self):
        """创建数据包生成标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("数据包输入")
        input_layout = QFormLayout()
        
        # CVE ID
        self.cve_id_input = QLineEdit()
        self.cve_id_input.setPlaceholderText("例如: CVE-2024-XXXX")
        input_layout.addRow("CVE 编号:", self.cve_id_input)
        
        # 数据包文件选择（仅文件，不支持手动粘贴内容）
        file_layout = QHBoxLayout()
        self.packet_file_input = QLineEdit()
        self.packet_file_input.setPlaceholderText("选择数据包文件...")
        self.packet_file_input.setReadOnly(True)  # 禁止手动输入，必须选择文件
        file_btn = QPushButton("浏览...")
        file_btn.clicked.connect(self.select_packet_file)
        file_layout.addWidget(self.packet_file_input)
        file_layout.addWidget(file_btn)
        input_layout.addRow("数据包文件:", file_layout)
        
        # 输出目录
        output_layout = QHBoxLayout()
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setPlaceholderText("默认: payloads/")
        output_btn = QPushButton("浏览...")
        output_btn.clicked.connect(self.select_output_dir)
        output_layout.addWidget(self.output_dir_input)
        output_layout.addWidget(output_btn)
        input_layout.addRow("输出目录:", output_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.parse_btn = QPushButton("拆解数据包")
        self.parse_btn.clicked.connect(self.parse_packet)
        button_layout.addWidget(self.parse_btn)
        
        self.generate_btn = QPushButton("生成并保存模板")
        self.generate_btn.clicked.connect(self.generate_template)
        button_layout.addWidget(self.generate_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 结果显示区域
        result_group = QGroupBox("拆解结果")
        result_layout = QVBoxLayout()
        
        self.parse_result_text = QTextEdit()
        self.parse_result_text.setReadOnly(True)
        self.parse_result_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.parse_result_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        widget.setLayout(layout)
        return widget
    
    def create_list_tab(self):
        """创建 Payload 列表标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        refresh_list_btn = QPushButton("刷新列表")
        refresh_list_btn.clicked.connect(self.refresh_payload_list_in_tab)
        button_layout.addWidget(refresh_list_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 列表显示
        self.payload_list = QListWidget()
        self.refresh_payload_list_in_tab()
        layout.addWidget(self.payload_list)
        
        widget.setLayout(layout)
        return widget
    
    def refresh_payload_list(self):
        """刷新 Payload 列表（用于下拉框）"""
        try:
            payloads_dir = os.path.join(current_dir, "payloads")
            if not os.path.exists(payloads_dir):
                return
            
            self.module_combo.clear()
            for filename in os.listdir(payloads_dir):
                if filename.endswith('.py') and not filename.startswith('__'):
                    # 跳过占位文件 init.py，避免被当成模块加载
                    if filename.lower() == 'init.py':
                        continue
                    module_name = filename[:-3]
                    try:
                        # 验证模块是否有效
                        self.manager.load_payload_module(module_name)
                        self.module_combo.addItem(module_name)
                    except:
                        continue
        except Exception as e:
            QMessageBox.warning(self, "警告", f"刷新列表失败: {e}")
    
    def refresh_payload_list_in_tab(self):
        """刷新 Payload 列表（用于列表标签页）"""
        try:
            payloads_dir = os.path.join(current_dir, "payloads")
            if not os.path.exists(payloads_dir):
                self.payload_list.clear()
                self.payload_list.addItem("未找到 payloads 目录")
                return
            
            self.payload_list.clear()
            count = 0
            for filename in sorted(os.listdir(payloads_dir)):
                if filename.endswith('.py') and not filename.startswith('__'):
                    # 跳过占位文件 init.py，避免被当成模块加载
                    if filename.lower() == 'init.py':
                        continue
                    module_name = filename[:-3]
                    try:
                        # 验证模块是否有效
                        self.manager.load_payload_module(module_name)
                        self.payload_list.addItem(module_name)
                        count += 1
                    except:
                        continue
            
            if count == 0:
                self.payload_list.addItem("未找到有效的 payload 模块")
        except Exception as e:
            QMessageBox.warning(self, "警告", f"刷新列表失败: {e}")
    
    def show_payload(self):
        """显示 Payload"""
        module_name = self.module_combo.currentText().strip()
        ip_port = self.ip_port_input.text().strip()
        cmd = self.cmd_input.text().strip()
        
        if not module_name:
            QMessageBox.warning(self, "警告", "请选择或输入 Payload 模块名")
            return
        if not ip_port:
            QMessageBox.warning(self, "警告", "请输入目标地址")
            return
        if not cmd:
            QMessageBox.warning(self, "警告", "请输入要执行的命令")
            return
        
        try:
            self.result_text.clear()
            self.result_text.append("正在生成 Payload...\n")
            
            payload_data = self.manager.generate_payload(module_name, ip_port, cmd)
            
            if payload_data is None:
                self.result_text.append("[!] Payload 生成失败")
                return
            
            # 显示结果
            self.result_text.append("=" * 60)
            self.result_text.append("Payload 信息:")
            self.result_text.append("=" * 60)
            self.result_text.append(f"模块: {module_name}")
            self.result_text.append(f"目标: {ip_port}")
            self.result_text.append(f"命令: {cmd}")
            self.result_text.append("=" * 60)
            self.result_text.append("\nHTTP 请求:")
            self.result_text.append("=" * 60)
            
            method = payload_data.get('method', 'POST')
            url = payload_data['url']
            headers = payload_data['headers']
            data = payload_data.get('data', None)
            
            # 构建原始请求
            request_lines = []
            request_lines.append(f"{method} {url} HTTP/1.1")
            for k, v in headers.items():
                request_lines.append(f"{k}: {v}")
            if data:
                request_lines.append("")
                if isinstance(data, dict):
                    import json
                    request_lines.append(json.dumps(data, indent=2))
                else:
                    request_lines.append(str(data))
            
            self.result_text.append("\n".join(request_lines))
            self.result_text.append("=" * 60)
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"显示 Payload 失败: {e}")
            self.result_text.append(f"[!] 错误: {e}")
    
    def send_payload(self):
        """发送 Payload"""
        module_name = self.module_combo.currentText().strip()
        ip_port = self.ip_port_input.text().strip()
        cmd = self.cmd_input.text().strip()
        timeout = self.timeout_spin.value()
        
        if not module_name:
            QMessageBox.warning(self, "警告", "请选择或输入 Payload 模块名")
            return
        if not ip_port:
            QMessageBox.warning(self, "警告", "请输入目标地址")
            return
        if not cmd:
            QMessageBox.warning(self, "警告", "请输入要执行的命令")
            return
        
        # 禁用按钮
        self.send_btn.setEnabled(False)
        self.send_btn.setText("发送中...")
        self.result_text.clear()
        self.result_text.append("正在发送 Payload...\n")
        
        # 创建工作线程
        self.worker = PayloadWorker(self.manager, module_name, ip_port, cmd, timeout)
        self.worker.finished.connect(self.on_send_finished)
        self.worker.error.connect(self.on_send_error)
        self.worker.start()

    def create_css_md5_tab(self):
        """创建 CSS MD5 计算标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("参数设置")
        input_layout = QFormLayout()
        
        # 页面URL
        self.css_page_url_input = QLineEdit()
        self.css_page_url_input.setPlaceholderText("例如: http://192.168.1.1:80/")
        input_layout.addRow("页面 URL:", self.css_page_url_input)
        
        # 超时时间
        self.css_timeout_spin = QSpinBox()
        self.css_timeout_spin.setRange(1, 300)
        self.css_timeout_spin.setValue(3)
        input_layout.addRow("超时时间(秒):", self.css_timeout_spin)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.css_calculate_btn = QPushButton("计算 CSS MD5")
        self.css_calculate_btn.clicked.connect(self.calculate_css_md5)
        button_layout.addWidget(self.css_calculate_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 结果显示区域
        result_group = QGroupBox("结果显示")
        result_layout = QVBoxLayout()
        
        self.css_result_text = QTextEdit()
        self.css_result_text.setReadOnly(True)
        self.css_result_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.css_result_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        widget.setLayout(layout)
        return widget
    
    def calculate_css_md5(self):
        """计算CSS文件的MD5值"""
        page_url = self.css_page_url_input.text().strip()
        timeout = self.css_timeout_spin.value()
        
        if not page_url:
            QMessageBox.warning(self, "警告", "请输入页面 URL")
            return
        
        if get_css_files_md5_from_page is None:
            QMessageBox.warning(self, "警告", "CSS MD5功能未加载")
            return
        
        # 禁用按钮
        self.css_calculate_btn.setEnabled(False)
        self.css_calculate_btn.setText("计算中...")
        self.css_result_text.clear()
        self.css_result_text.append("正在访问页面并提取CSS文件...\n")
        
        # 创建工作线程
        self.css_worker = CSSMD5Worker(page_url, timeout)
        self.css_worker.finished.connect(self.on_css_md5_finished)
        self.css_worker.error.connect(self.on_css_md5_error)
        self.css_worker.start()
    
    def on_css_md5_finished(self, css_md5_dict):
        """CSS MD5计算完成回调，并匹配CVE（精简回显格式）"""
        self.css_calculate_btn.setEnabled(True)
        self.css_calculate_btn.setText("计算 CSS MD5")
        
        if not css_md5_dict:
            self.css_result_text.append("[!] 未找到CSS文件或访问页面失败")
            QMessageBox.warning(self, "警告", "未找到CSS文件或访问页面失败")
            return
        
        self.css_result_text.clear()
        self.css_result_text.append("=" * 60)
        self.css_result_text.append("CSS 文件 MD5 计算结果")
        self.css_result_text.append("=" * 60)
        self.css_result_text.append(f"找到 {len(css_md5_dict)} 个CSS文件")
        
        success_count = 0
        matched_cve = 0
        matched_cve_set = set()
        for css_url, info in css_md5_dict.items():
            if isinstance(info, tuple):
                md5_hash, cve_id = info
            else:
                md5_hash, cve_id = info, None
            
            self.css_result_text.append("-" * 60)
            self.css_result_text.append(f"URL : {css_url}")
            if md5_hash:
                self.css_result_text.append(f"MD5 : {md5_hash}")
                if cve_id:
                    self.css_result_text.append(f"CVE : {cve_id}")
                    matched_cve += 1
                    matched_cve_set.add(cve_id)
                else:
                    self.css_result_text.append("CVE : (未匹配)")
                success_count += 1
            else:
                self.css_result_text.append("MD5 : (下载失败)")
                self.css_result_text.append("CVE : -")
        
        self.css_result_text.append("=" * 60)
        self.css_result_text.append(f"成功: {success_count}/{len(css_md5_dict)}")
        if matched_cve_set:
            self.css_result_text.append(f"匹配到的 CVE 列表: {', '.join(sorted(matched_cve_set))}")
        
        if success_count > 0:
            QMessageBox.information(self, "成功", f"成功计算 {success_count} 个CSS文件的MD5值，匹配到 {matched_cve} 个CVE")
        else:
            QMessageBox.warning(self, "警告", "所有CSS文件下载失败")
    
    def on_css_md5_error(self, error_msg):
        """CSS MD5计算错误回调"""
        self.css_calculate_btn.setEnabled(True)
        self.css_calculate_btn.setText("计算 CSS MD5")
        self.css_result_text.append(f"[!] 错误: {error_msg}")
        QMessageBox.critical(self, "错误", f"计算失败: {error_msg}")
    
    def create_fingerprint_tab(self):
        """创建指纹-CVE映射管理标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("添加/更新映射")
        input_layout = QFormLayout()
        
        # 指纹输入
        self.fp_fingerprint_input = QLineEdit()
        self.fp_fingerprint_input.setPlaceholderText("例如: abc123def456... (MD5值)")
        input_layout.addRow("指纹:", self.fp_fingerprint_input)
        
        # CVE输入
        self.fp_cve_input = QLineEdit()
        self.fp_cve_input.setPlaceholderText("例如: CVE-2024-XXXX (留空表示无CVE)")
        input_layout.addRow("CVE编号:", self.fp_cve_input)
        
        # 描述输入
        self.fp_description_input = QLineEdit()
        self.fp_description_input.setPlaceholderText("可选描述信息")
        input_layout.addRow("描述:", self.fp_description_input)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.fp_add_btn = QPushButton("添加/更新映射")
        self.fp_add_btn.clicked.connect(self.add_fingerprint_mapping)
        button_layout.addWidget(self.fp_add_btn)
        
        self.fp_remove_btn = QPushButton("删除映射")
        self.fp_remove_btn.clicked.connect(self.remove_fingerprint_mapping)
        button_layout.addWidget(self.fp_remove_btn)
        
        self.fp_refresh_btn = QPushButton("刷新列表")
        self.fp_refresh_btn.clicked.connect(self.refresh_fingerprint_list)
        button_layout.addWidget(self.fp_refresh_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 映射列表区域
        list_group = QGroupBox("映射列表")
        list_layout = QVBoxLayout()
        
        self.fp_list_widget = QListWidget()
        self.fp_list_widget.setFont(QFont("Consolas", 9))
        list_layout.addWidget(self.fp_list_widget)
        
        list_group.setLayout(list_layout)
        layout.addWidget(list_group)
        
        widget.setLayout(layout)
        
        # 初始化列表
        self.refresh_fingerprint_list()
        
        return widget
    
    def add_fingerprint_mapping(self):
        """添加或更新指纹-CVE映射"""
        if get_manager is None:
            QMessageBox.warning(self, "警告", "指纹-CVE映射模块未加载")
            return
        
        fingerprint = self.fp_fingerprint_input.text().strip()
        cve_id = self.fp_cve_input.text().strip() or None
        description = self.fp_description_input.text().strip() or None
        
        if not fingerprint:
            QMessageBox.warning(self, "警告", "请输入指纹")
            return
        
        manager = get_manager()
        if manager.add_mapping(fingerprint, cve_id, description):
            QMessageBox.information(self, "成功", f"成功添加映射: {fingerprint} -> {cve_id or '(无CVE)'}")
            # 清空输入框
            self.fp_fingerprint_input.clear()
            self.fp_cve_input.clear()
            self.fp_description_input.clear()
            # 刷新列表
            self.refresh_fingerprint_list()
        else:
            QMessageBox.warning(self, "失败", "添加映射失败")
    
    def remove_fingerprint_mapping(self):
        """删除指纹-CVE映射"""
        if get_manager is None:
            QMessageBox.warning(self, "警告", "指纹-CVE映射模块未加载")
            return
        
        current_item = self.fp_list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(self, "警告", "请先选择要删除的映射")
            return
        
        # 从显示文本中提取指纹（格式：指纹: xxx）
        text = current_item.text()
        if "指纹:" in text:
            fingerprint = text.split("指纹:")[1].split("\n")[0].strip()
        else:
            QMessageBox.warning(self, "警告", "无法解析指纹信息")
            return
        
        reply = QMessageBox.question(self, "确认", f"确定要删除指纹 {fingerprint} 的映射吗？",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            manager = get_manager()
            if manager.remove_mapping(fingerprint):
                QMessageBox.information(self, "成功", "删除成功")
                self.refresh_fingerprint_list()
            else:
                QMessageBox.warning(self, "失败", "删除失败")
    
    def refresh_fingerprint_list(self):
        """刷新指纹-CVE映射列表"""
        if get_manager is None:
            self.fp_list_widget.clear()
            self.fp_list_widget.addItem("指纹-CVE映射模块未加载")
            return
        
        manager = get_manager()
        mappings = manager.get_all_mappings()
        
        self.fp_list_widget.clear()
        
        if not mappings:
            self.fp_list_widget.addItem("暂无映射")
        else:
            for mapping in mappings:
                item_text = f"指纹: {mapping.fingerprint}\n"
                item_text += f"CVE: {mapping.cve_id or '(无CVE)'}\n"
                if mapping.description:
                    item_text += f"描述: {mapping.description}"
                self.fp_list_widget.addItem(item_text)
    
    def _pretty_json(self, text: str) -> str:
        """尝试将文本格式化为JSON，失败则原样返回。"""
        import json
        try:
            return json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except Exception:
            return text

    def on_send_finished(self, response):
        """发送完成回调"""
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送 Payload")
        
        # requests.Response 在 4xx/5xx 时布尔为 False，需显式判空
        if response is None:
            self.result_text.append("[!] 发送失败")
            return

        req = response.request

        # 请求回显
        self.result_text.append("=" * 60)
        self.result_text.append("请求 (回显):")
        self.result_text.append("=" * 60)
        self.result_text.append(f"{req.method} {req.url}")
        for k, v in req.headers.items():
            self.result_text.append(f"{k}: {v}")
        if req.body:
            self.result_text.append("")
            try:
                body_text = req.body.decode() if isinstance(req.body, (bytes, bytearray)) else str(req.body)
            except Exception:
                body_text = str(req.body)
            self.result_text.append(body_text)

        # 响应回显
        self.result_text.append("\n" + "=" * 60)
        self.result_text.append("响应:")
        self.result_text.append("=" * 60)
        self.result_text.append(f"状态码: {response.status_code}")
        self.result_text.append(f"URL: {response.url}")
        self.result_text.append(f"耗时: {getattr(response, 'elapsed', '')}")
        self.result_text.append("\n响应头:")
        for k, v in response.headers.items():
            self.result_text.append(f"  {k}: {v}")
        self.result_text.append("\n响应体:")
        self.result_text.append(self._pretty_json(response.text))
        self.result_text.append("=" * 60)
    
    def on_send_error(self, error_msg):
        """发送错误回调"""
        self.send_btn.setEnabled(True)
        self.send_btn.setText("发送 Payload")
        self.result_text.append(f"[!] 错误: {error_msg}")
        QMessageBox.critical(self, "错误", f"发送失败: {error_msg}")
    
    def select_packet_file(self):
        """选择数据包文件"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "选择数据包文件", "", "文本文件 (*.txt);;所有文件 (*.*)"
        )
        if file_path:
            self.packet_file_input.setText(file_path)
    
    def select_output_dir(self):
        """选择输出目录"""
        dir_path = QFileDialog.getExistingDirectory(
            self, "选择输出目录", ""
        )
        if dir_path:
            self.output_dir_input.setText(dir_path)
    
    def parse_packet(self):
        """拆解数据包（仅支持选择文件，不允许直接输入内容）"""
        cve_id = self.cve_id_input.text().strip()
        packet_file = self.packet_file_input.text().strip()
        
        if not cve_id:
            QMessageBox.warning(self, "警告", "请输入 CVE 编号")
            return
        
        if not packet_file:
            QMessageBox.warning(self, "警告", "请选择数据包文件")
            return
        
        if not os.path.exists(packet_file):
            QMessageBox.warning(self, "警告", "数据包文件不存在")
            return
        
        try:
            # 读取数据包
            packet = read_packet_file(packet_file)
            
            # 拆解数据包
            self.parse_result_text.clear()
            self.parse_result_text.append("正在拆解数据包...\n")
            
            result = generate_from_packet(
                packet=packet,
                cve_id=cve_id,
                save=False,
                output_dir=None,
                gui_mode=True
            )
            
            if result and not result.get('_error'):
                output_text = result.get('_output_text', '')
                self.parse_result_text.clear()
                self.parse_result_text.append(output_text)
            else:
                error_text = result.get('_output_text', '拆解失败') if result else '拆解失败'
                self.parse_result_text.append(f"\n[!] {error_text}")
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"拆解失败: {e}")
            self.parse_result_text.append(f"[!] 错误: {e}")
    
    def generate_template(self):
        """生成并保存模板（仅支持选择文件，不允许直接输入内容）"""
        cve_id = self.cve_id_input.text().strip()
        packet_file = self.packet_file_input.text().strip()
        output_dir = self.output_dir_input.text().strip() or None
        
        if not cve_id:
            QMessageBox.warning(self, "警告", "请输入 CVE 编号")
            return
        
        if not packet_file:
            QMessageBox.warning(self, "警告", "请选择数据包文件")
            return
        
        if not os.path.exists(packet_file):
            QMessageBox.warning(self, "警告", "数据包文件不存在")
            return
        
        try:
            # 读取数据包
            packet = read_packet_file(packet_file)
            
            # 生成模板
            self.parse_result_text.clear()
            self.parse_result_text.append("正在生成模板...\n")
            
            result = generate_from_packet(
                packet=packet,
                cve_id=cve_id,
                save=True,
                output_dir=output_dir,
                gui_mode=True
            )
            
            if result and not result.get('_error'):
                output_text = result.get('_output_text', '')
                self.parse_result_text.clear()
                self.parse_result_text.append(output_text)
                
                # 从输出文本中提取文件路径
                import re
                path_match = re.search(r'模板已生成: (.+)', output_text)
                if path_match:
                    file_path = path_match.group(1)
                    QMessageBox.information(self, "成功", f"模板已保存到:\n{file_path}")
                else:
                    QMessageBox.information(self, "成功", "模板生成成功！")
                
                # 刷新列表
                self.refresh_payload_list()
                self.refresh_payload_list_in_tab()
            else:
                error_text = result.get('_output_text', '模板生成失败') if result else '模板生成失败'
                self.parse_result_text.append(f"\n[!] {error_text}")
                QMessageBox.warning(self, "警告", error_text)
                
        except Exception as e:
            QMessageBox.critical(self, "错误", f"生成失败: {e}")
            self.parse_result_text.append(f"[!] 错误: {e}")


def main():
    """主函数"""
    if not PYQT5_AVAILABLE:
        print("[!] 错误: PyQt5 未安装")
        print("请安装: pip install PyQt5")
        sys.exit(1)
    
    # 在创建 QApplication 之前设置高 DPI 缩放
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    app = QApplication(sys.argv)
    app.setApplicationName("CVE Payload Tool")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

