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
                                 QProgressBar, QListWidget, QSplitter)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QFont, QTextCursor
    PYQT5_AVAILABLE = True
except ImportError:
    PYQT5_AVAILABLE = False
    print("[!] 错误: PyQt5 未安装")
    print("请安装: pip install PyQt5")
    sys.exit(1)

# 导入核心模块
from poc_tool import (PayloadManager, generate_from_packet,
                      read_packet_file, list_payloads)

try:
    # 指纹探测（是否有 Web / Drupal 等）
    from fingerprint import fingerprint_and_select_poc
except ImportError:
    fingerprint_and_select_poc = None

try:
    # 指纹注册表（固有文件 -> PoC 函数）
    from fingerprint_registry import add_fingerprint as fp_add_fingerprint, match_and_execute as fp_match_and_execute
except ImportError:
    fp_add_fingerprint = None
    fp_match_and_execute = None


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


class MainWindow(QMainWindow):
    """主窗口"""
    
    def __init__(self):
        super().__init__()
        self.manager = PayloadManager(debug=False)
        self._register_builtin_fingerprints()
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

        # 指纹自动 POC 按钮（根据 IP 进行指纹识别并触发 PoC）
        self.auto_btn = QPushButton("指纹自动 PoC")
        self.auto_btn.clicked.connect(self.auto_fingerprint_poc)
        button_layout.addWidget(self.auto_btn)
        
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

    def _register_builtin_fingerprints(self):
        """
        在 GUI 启动时注册内置的“固有文件指纹 -> PoC”映射。
        与命令行逻辑保持一致：目前示例为 Drupal /core/CHANGELOG.txt -> CVE_2019_6340。
        """
        if fp_add_fingerprint is None:
            return

        def drupal_changelog_poc(target_info: dict):
            """
            通过文件指纹触发的 Drupal PoC。
            target_info 约定包含：
              - ip: 目标 IP
              - port: 目标 Web 端口
              - cmd: 要执行的命令
              - timeout: 超时时间（秒）
            """
            ip = target_info.get("ip")
            port = target_info.get("port")
            cmd = target_info.get("cmd", "whoami")
            timeout = int(target_info.get("timeout", 10))

            if not ip or not port:
                raise ValueError("指纹 PoC 缺少 ip 或 port 信息")

            ip_port = f"{ip}:{port}"
            manager = PayloadManager(debug=False)
            return manager.send_payload("CVE_2019_6340", ip_port, cmd, timeout=timeout)

        try:
            fp_add_fingerprint(
                fp_id="drupal_core_changelog",
                file_path="/core/CHANGELOG.txt",
                file_hash=None,
                poc_function=drupal_changelog_poc,
            )
        except Exception:
            # 已注册或其他错误时忽略，避免 GUI 因重复注册崩溃
            pass
    
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
        
        # 数据包文件选择
        file_layout = QHBoxLayout()
        self.packet_file_input = QLineEdit()
        self.packet_file_input.setPlaceholderText("选择数据包文件...")
        file_btn = QPushButton("浏览...")
        file_btn.clicked.connect(self.select_packet_file)
        file_layout.addWidget(self.packet_file_input)
        file_layout.addWidget(file_btn)
        input_layout.addRow("数据包文件:", file_layout)
        
        # 数据包文本输入
        self.packet_text = QTextEdit()
        self.packet_text.setPlaceholderText("或直接在此输入 HTTP 数据包内容...")
        self.packet_text.setMaximumHeight(150)
        input_layout.addRow("数据包内容:", self.packet_text)
        
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

    def auto_fingerprint_poc(self):
        """使用指纹识别 + 指纹注册表，在 GUI 中自动选择并发送 PoC。"""
        ip_port_text = self.ip_port_input.text().strip()
        cmd = self.cmd_input.text().strip() or "whoami"
        timeout = self.timeout_spin.value()

        if not ip_port_text:
            QMessageBox.warning(self, "警告", "请输入目标地址（例如 192.168.1.1:80 或 192.168.1.1）")
            return

        # 从输入中提取 IP（忽略端口，指纹识别模块会自行扫描端口）
        if ":" in ip_port_text:
            ip = ip_port_text.split(":", 1)[0]
        else:
            ip = ip_port_text

        if fingerprint_and_select_poc is None or fp_match_and_execute is None:
            QMessageBox.warning(self, "警告", "指纹模块或指纹注册表未正确加载，无法使用自动 PoC 功能")
            return

        self.result_text.clear()
        self.result_text.append("正在进行指纹识别并自动选择 PoC...\n")

        try:
            fp = fingerprint_and_select_poc(ip)
        except Exception as e:
            QMessageBox.critical(self, "错误", f"指纹识别失败: {e}")
            self.result_text.append(f"[!] 指纹识别失败: {e}")
            return

        # 展示指纹识别结果
        self.result_text.append("=" * 60)
        self.result_text.append("指纹识别结果:")
        self.result_text.append("=" * 60)
        self.result_text.append(f"目标 IP: {ip}")
        self.result_text.append(f"是否存在 Web 服务: {fp.has_web} (端口: {fp.web_ports})")
        self.result_text.append(f"Web 固有文件指纹: {fp.web_fingerprints}")
        if fp.web_file_hashes:
            self.result_text.append("Web 文件 MD5 哈希值:")
            for file_path, md5_hash in fp.web_file_hashes.items():
                self.result_text.append(f"  {file_path}: {md5_hash}")
        self.result_text.append(f"是否存在数据库端口: {fp.has_db} (详情: {fp.db_ports})")
        self.result_text.append(f"选择理由: {fp.reason}")
        self.result_text.append("")

        # 目前示例性支持 Drupal 指纹 -> /core/CHANGELOG.txt -> CVE_2019_6340
        if fp.has_web and fp.web_ports and "drupal" in fp.web_fingerprints:
            web_port = fp.web_ports[0]
            self.result_text.append("[+] 检测到 Drupal 固有文件指纹，尝试通过指纹注册表触发 PoC...\n")
            try:
                response = fp_match_and_execute(
                    target_file_path="/core/CHANGELOG.txt",
                    target_file_hash=None,
                    extra_target_info={
                        "ip": ip,
                        "port": web_port,
                        "cmd": cmd,
                        "timeout": timeout,
                    },
                )
                # 复用已有的响应展示逻辑
                self.on_send_finished(response)
            except Exception as e:
                QMessageBox.critical(self, "错误", f"指纹注册表执行 PoC 失败: {e}")
                self.result_text.append(f"[!] 指纹注册表执行 PoC 失败: {e}")
        else:
            self.result_text.append("[!] 未检测到可用的 Web 固有文件指纹，当前未自动触发任何 PoC。")
    
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
        """拆解数据包"""
        cve_id = self.cve_id_input.text().strip()
        packet_file = self.packet_file_input.text().strip()
        packet_text = self.packet_text.toPlainText().strip()
        
        if not cve_id:
            QMessageBox.warning(self, "警告", "请输入 CVE 编号")
            return
        
        if not packet_file and not packet_text:
            QMessageBox.warning(self, "警告", "请选择数据包文件或输入数据包内容")
            return
        
        try:
            # 读取数据包
            if packet_file:
                if not os.path.exists(packet_file):
                    QMessageBox.warning(self, "警告", "数据包文件不存在")
                    return
                packet = read_packet_file(packet_file)
            else:
                packet = packet_text
            
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
        """生成并保存模板"""
        cve_id = self.cve_id_input.text().strip()
        packet_file = self.packet_file_input.text().strip()
        packet_text = self.packet_text.toPlainText().strip()
        output_dir = self.output_dir_input.text().strip() or None
        
        if not cve_id:
            QMessageBox.warning(self, "警告", "请输入 CVE 编号")
            return
        
        if not packet_file and not packet_text:
            QMessageBox.warning(self, "警告", "请选择数据包文件或输入数据包内容")
            return
        
        try:
            # 读取数据包
            if packet_file:
                if not os.path.exists(packet_file):
                    QMessageBox.warning(self, "警告", "数据包文件不存在")
                    return
                packet = read_packet_file(packet_file)
            else:
                packet = packet_text
            
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

