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
    # 端口扫描功能
    from port_scanner import scan_ports, format_scan_result
except ImportError:
    scan_ports = None
    format_scan_result = None

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


class AutoTestWorker(QThread):
    """自动化测试工作线程"""
    log_signal = pyqtSignal(str)
    detail_signal = pyqtSignal(dict)  # {'cve':str,'executed_ports':list,'success':bool,'success_port':int|None}
    finished = pyqtSignal(int, int)  # success_count, total_count
    error = pyqtSignal(str)
    
    def __init__(self, url, cmd, fp_timeout, send_timeout, do_port_scan: bool = False,
                 ports: list = None, port_timeout: int = 2):
        super().__init__()
        self.url = url
        self.cmd = cmd
        self.fp_timeout = fp_timeout
        self.send_timeout = send_timeout
        # 端口扫描配置
        self.do_port_scan = do_port_scan
        self.ports = ports
        self.port_timeout = port_timeout
    
    def run(self):
        try:
            from urllib.parse import urlparse
            
            self.log_signal.emit("=" * 60)
            self.log_signal.emit("自动化测试")
            self.log_signal.emit("=" * 60)
            self.log_signal.emit(f"目标: {self.url}")
            self.log_signal.emit(f"执行命令: {self.cmd}")
            self.log_signal.emit("=" * 60 + "\n")

            # 步骤1：端口扫描 -> 对每个开放端口进行指纹识别
            self.log_signal.emit("[*] 步骤1: 端口扫描（若启用）并对开放端口进行指纹识别...")

            # 解析主机与提供的端口
            provided_port = None
            base_host = ""
            if '://' in self.url:
                parsed = urlparse(self.url)
                base_host = parsed.hostname or ''
                provided_port = parsed.port
            else:
                if ':' in self.url:
                    try:
                        host_part, port_part = self.url.rsplit(':', 1)
                        base_host = host_part
                        provided_port = int(port_part)
                    except Exception:
                        base_host = self.url
                        provided_port = None
                else:
                    base_host = self.url
                    provided_port = None

            # 进行端口扫描（若启用），否则使用提供的端口或默认80
            ports_to_scan = [provided_port] if provided_port else [80]
            open_ports = []
            if self.do_port_scan and scan_ports is not None:
                try:
                    self.log_signal.emit(f"    [+] 扫描目标: {base_host}")
                    scan_results = scan_ports(base_host, self.ports, timeout=self.port_timeout)
                    open_ports = sorted([p for p, (is_open, _) in scan_results.items() if is_open])
                    if open_ports:
                        self.log_signal.emit(f"    [+] 发现开放端口: {', '.join(str(p) for p in open_ports)}")
                    else:
                        self.log_signal.emit("    [-] 未发现开放端口，使用提供端口或默认 80")
                        open_ports = ports_to_scan
                except Exception as e:
                    self.log_signal.emit(f"[!] 端口扫描出错: {e}")
                    open_ports = ports_to_scan
            else:
                open_ports = ports_to_scan

            # 对每个开放端口做指纹识别，收集匹配到的 CVE（按端口映射）
            if get_css_files_md5_from_page is None:
                self.error.emit("指纹模块未加载")
                return

            matched_cves_per_port = {}  # cve -> set(ports)
            for port in open_ports:
                try:
                    url_for_fp = f"http://{base_host}:{port}/"
                    self.log_signal.emit(f"    [*] 对 {url_for_fp} 进行指纹识别...")
                    css_md5_dict = get_css_files_md5_from_page(url_for_fp, self.fp_timeout)
                    if not css_md5_dict:
                        self.log_signal.emit(f"    [-] {url_for_fp} 未提取到 CSS 或访问失败")
                        continue

                    for css_url, info in css_md5_dict.items():
                        if isinstance(info, tuple):
                            md5_hash, cve_id = info
                        else:
                            md5_hash, cve_id = info, None
                        if md5_hash:
                            self.log_signal.emit(f"        [+] {css_url} MD5: {md5_hash} {'CVE: '+cve_id if cve_id else ''}")
                            if cve_id:
                                matched_cves_per_port.setdefault(cve_id, set()).add(port)
                except Exception as e:
                    self.log_signal.emit(f"    [!] 指纹识别出错 ({base_host}:{port}): {e}")

            matched_cves = set(matched_cves_per_port.keys())
            if not matched_cves:
                self.error.emit("未匹配到任何CVE，自动化测试结束")
                return

            self.log_signal.emit(f"\n[+] 匹配到的 CVE: {', '.join(sorted(matched_cves))}")

            # 步骤2：执行Payload
            self.log_signal.emit(f"\n[*] 步骤2: 执行Payload...")
            
            # 确定待测试的主机与端口列表
            base_host = ""
            provided_port = None
            if '://' in self.url:
                parsed = urlparse(self.url)
                base_host = parsed.hostname or ''
                provided_port = parsed.port
            else:
                # 处理 IP 或 IP:port 情况
                if ':' in self.url:
                    try:
                        host_part, port_part = self.url.rsplit(':', 1)
                        base_host = host_part
                        provided_port = int(port_part)
                    except Exception:
                        base_host = self.url
                        provided_port = None
                else:
                    base_host = self.url

            payload_manager = PayloadManager(debug=False)
            success_count = 0
            total_cves = len(matched_cves)

            # 对每个匹配到的 CVE，只在该 CVE 匹配到的端口上执行对应 Payload
            for cve_id in sorted(matched_cves):
                module_name = cve_id.replace('-', '_')
                ports_for_cve = sorted(matched_cves_per_port.get(cve_id, [])) or []

                self.log_signal.emit(f"\n{'='*60}")
                self.log_signal.emit(f"[*] 尝试执行 Payload: {module_name}")
                self.log_signal.emit(f"    匹配端口: {', '.join(str(p) for p in ports_for_cve) if ports_for_cve else '(无)'}")
                self.log_signal.emit("=" * 60)

                cve_success = False
                success_port = None

                if not ports_for_cve:
                    self.log_signal.emit(f"    [!] 未在任何端口匹配到 {module_name} 的指纹，跳过执行")
                else:
                    for port in ports_for_cve:
                        ip_port = f"{base_host}:{port}"
                        self.log_signal.emit(f"    [*] 目标: {ip_port}，执行命令: {self.cmd}")
                        try:
                            result = payload_manager.send_payload_safe(
                                module_name, ip_port, self.cmd,
                                timeout=self.send_timeout,
                                log_callback=lambda msg: self.log_signal.emit(f"    {msg}")
                            )
                            if result is not None:
                                response_text = result.text if hasattr(result, 'text') else str(result)
                                if 'www-data' in response_text:
                                    cve_success = True
                                    success_count += 1
                                    success_port = port
                                    self.log_signal.emit(f"    [+] {module_name} 在 {ip_port} 执行成功！检测到 www-data")
                                    break
                                else:
                                    self.log_signal.emit(f"    [-] {module_name} 在 {ip_port} 响应未检测到 www-data")
                            else:
                                self.log_signal.emit(f"    [-] {module_name} 在 {ip_port} 无响应")
                        except Exception as e:
                            self.log_signal.emit(f"    [!] {module_name} 在 {ip_port} 执行出错: {e}")

                # 发送单个 CVE 详情到 UI（用于表格展示）
                try:
                    self.detail_signal.emit({
                        "cve": cve_id,
                        "executed_ports": ports_for_cve,
                        "success": cve_success,
                        "success_port": success_port
                    })
                except Exception:
                    pass

            # 最终输出：列出匹配到的 CVE，并给出统计
            self.log_signal.emit("\n" + "=" * 60)
            self.log_signal.emit(f"匹配到的 CVE 列表: {', '.join(sorted(matched_cves))}")
            self.log_signal.emit(f"成功执行的 CVE 数: {success_count}/{total_cves}")
            self.finished.emit(success_count, total_cves)
            
        except Exception as e:
            self.error.emit(str(e))

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
            if scan_ports is None:
                self.error.emit("端口扫描模块未加载")
                return
            results = scan_ports(self.host, self.ports, timeout=self.timeout, max_workers=self.max_workers)
            self.finished.emit(results)
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
        
        # 端口扫描标签页
        portscan_tab = self.create_portscan_tab()
        tabs.addTab(portscan_tab, "端口扫描")
        
        # 指纹-CVE映射管理标签页
        if get_manager is not None:
            mapping_tab = self.create_fingerprint_tab()
            tabs.addTab(mapping_tab, "指纹-CVE映射")
        
        # 自动化测试标签页
        if get_css_files_md5_from_page is not None:
            auto_tab = self.create_auto_test_tab()
            tabs.addTab(auto_tab, "自动化测试")
        
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
    
    def create_portscan_tab(self):
        """创建端口扫描标签页"""
        widget = QWidget()
        layout = QVBoxLayout()

        # 输入区域
        input_group = QGroupBox("参数设置")
        input_layout = QFormLayout()

        # 目标主机
        self.port_host_input = QLineEdit()
        self.port_host_input.setPlaceholderText("例如: 192.168.1.1 或 example.com")
        input_layout.addRow("目标主机:", self.port_host_input)

        # 端口（列表或范围）
        self.port_ports_input = QLineEdit()
        self.port_ports_input.setPlaceholderText("例如: 80,443 或 1-1024（留空表示常见端口）")
        input_layout.addRow("端口:", self.port_ports_input)

        # 超时时间
        self.port_timeout_spin = QSpinBox()
        self.port_timeout_spin.setRange(1, 30)
        self.port_timeout_spin.setValue(2)
        input_layout.addRow("超时时间(秒):", self.port_timeout_spin)

        input_group.setLayout(input_layout)
        layout.addWidget(input_group)

        # 按钮区域
        button_layout = QHBoxLayout()
        self.portscan_start_btn = QPushButton("开始扫描")
        self.portscan_start_btn.clicked.connect(self.start_port_scan)
        button_layout.addWidget(self.portscan_start_btn)

        self.portscan_clear_btn = QPushButton("清空结果")
        self.portscan_clear_btn.clicked.connect(lambda: self.portscan_result_text.clear())
        button_layout.addWidget(self.portscan_clear_btn)

        button_layout.addStretch()
        layout.addLayout(button_layout)

        # 结果显示区域
        result_group = QGroupBox("扫描结果")
        result_layout = QVBoxLayout()
        self.portscan_result_text = QTextEdit()
        self.portscan_result_text.setReadOnly(True)
        self.portscan_result_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.portscan_result_text)
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)

        widget.setLayout(layout)
        return widget

    def start_port_scan(self):
        """开始端口扫描"""
        host = self.port_host_input.text().strip()
        ports_text = self.port_ports_input.text().strip()
        timeout = self.port_timeout_spin.value()

        if not host:
            QMessageBox.warning(self, "警告", "请输入目标主机")
            return

        # 解析端口输入
        ports = None
        if ports_text:
            try:
                if '-' in ports_text and ',' not in ports_text:
                    start, end = ports_text.split('-')
                    ports = list(range(int(start), int(end) + 1))
                else:
                    ports = [int(p.strip()) for p in ports_text.split(',') if p.strip()]
            except Exception:
                QMessageBox.warning(self, "警告", "端口格式错误，请使用逗号分隔或范围（如 80,443 或 1-1024）")
                return

        # 禁用按钮
        self.portscan_start_btn.setEnabled(False)
        self.portscan_start_btn.setText("扫描中...")
        self.portscan_result_text.clear()
        self.portscan_result_text.append(f"开始扫描 {host} ...\n")

        # 创建工作线程
        self.portscan_worker = PortScanWorker(host, ports=ports, timeout=timeout)
        self.portscan_worker.finished.connect(self.on_port_scan_finished)
        self.portscan_worker.error.connect(self.on_port_scan_error)
        self.portscan_worker.start()

    def on_port_scan_finished(self, results):
        """端口扫描完成回调"""
        self.portscan_start_btn.setEnabled(True)
        self.portscan_start_btn.setText("开始扫描")
        try:
            if format_scan_result is not None:
                output = format_scan_result(results)
            else:
                # 简易格式化
                lines = []
                open_ports = [(p, s) for p, (is_open, s) in sorted(results.items()) if is_open]
                if open_ports:
                    lines.append(f"开放的端口 ({len(open_ports)} 个):")
                    for p, s in open_ports:
                        lines.append(f"  {p}/tcp  open  {s or 'Unknown'}")
                else:
                    lines.append("未发现开放的端口")
                lines.append(f"\n已扫描 {len(results)} 个端口")
                output = "\n".join(lines)
            self.portscan_result_text.append(output)
        except Exception as e:
            self.portscan_result_text.append(f"[!] 处理结果出错: {e}")

    def on_port_scan_error(self, error_msg):
        """端口扫描错误回调"""
        self.portscan_start_btn.setEnabled(True)
        self.portscan_start_btn.setText("开始扫描")
        self.portscan_result_text.append(f"[!] 错误: {error_msg}")
        QMessageBox.critical(self, "错误", f"端口扫描失败: {error_msg}")
    
    def create_auto_test_tab(self):
        """创建自动化测试标签页"""
        widget = QWidget()
        layout = QVBoxLayout()
        
        # 输入区域
        input_group = QGroupBox("参数设置")
        input_layout = QFormLayout()
        
        # 目标 IP（仅输入 IP 或 IP:端口，例如 192.168.1.1 或 192.168.1.1:8080）
        self.auto_url_input = QLineEdit()
        self.auto_url_input.setPlaceholderText("例如: 192.168.1.1 或 192.168.1.1:8080")
        input_layout.addRow("目标 IP:", self.auto_url_input)
        
        # （仅保留目标 IP 输入，其他参数使用默认值）
        # 启用端口扫描复选框（用户可选择是否在自动化测试前进行端口扫描）
        from PyQt5.QtWidgets import QCheckBox
        self.auto_portscan_chk = QCheckBox()
        self.auto_portscan_chk.setChecked(False)
        input_layout.addRow("启用端口扫描:", self.auto_portscan_chk)

        # 自定义端口输入（可留空，格式：80,443 或 1-1000）
        self.auto_ports_input = QLineEdit()
        self.auto_ports_input.setPlaceholderText("可选: 例如 80,443 或 1-1024（留空使用常见端口）")
        input_layout.addRow("自定义扫描端口:", self.auto_ports_input)

        # 端口超时（秒）
        self.auto_port_timeout_spin = QSpinBox()
        self.auto_port_timeout_spin.setRange(1, 30)
        self.auto_port_timeout_spin.setValue(2)
        input_layout.addRow("端口超时(秒):", self.auto_port_timeout_spin)
        
        # 全量端口 / 常用端口 复选框
        self.auto_use_all_ports_chk = QCheckBox("全量端口 (1-65535)")
        self.auto_use_all_ports_chk.setChecked(False)
        self.auto_use_common_ports_chk = QCheckBox("常用端口")
        self.auto_use_common_ports_chk.setChecked(True)
        # 将两个复选框放在一行
        hbox = QHBoxLayout()
        hbox.addWidget(self.auto_use_all_ports_chk)
        hbox.addWidget(self.auto_use_common_ports_chk)
        input_layout.addRow("端口集合选项:", hbox)
        
        # 连接交互信号，控制互斥与启用状态
        try:
            self.auto_portscan_chk.toggled.connect(self.on_auto_portscan_toggled)
            self.auto_use_all_ports_chk.toggled.connect(self.on_auto_ports_option_changed)
            self.auto_use_common_ports_chk.toggled.connect(self.on_auto_ports_option_changed)
            self.auto_ports_input.textChanged.connect(self.on_auto_ports_input_changed)
        except Exception:
            pass

        # 初始根据端口扫描复选框设置控件可用性（默认未勾选端口扫描时禁用端口选项）
        try:
            self.on_auto_portscan_toggled(self.auto_portscan_chk.isChecked())
        except Exception:
            pass
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # 按钮区域
        button_layout = QHBoxLayout()
        
        self.auto_test_btn = QPushButton("开始自动化测试")
        self.auto_test_btn.clicked.connect(self.start_auto_test)
        button_layout.addWidget(self.auto_test_btn)
        
        self.auto_clear_btn = QPushButton("清空日志")
        self.auto_clear_btn.clicked.connect(lambda: self.auto_result_text.clear())
        button_layout.addWidget(self.auto_clear_btn)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        # 结果显示区域
        result_group = QGroupBox("执行日志")
        result_layout = QVBoxLayout()
        
        self.auto_result_text = QTextEdit()
        self.auto_result_text.setReadOnly(True)
        self.auto_result_text.setFont(QFont("Consolas", 10))
        result_layout.addWidget(self.auto_result_text)
        
        result_group.setLayout(result_layout)
        layout.addWidget(result_group)
        
        # 结果汇总表格（每个匹配到的 CVE 的执行状态）
        summary_group = QGroupBox("结果汇总")
        summary_layout = QVBoxLayout()
        self.auto_result_table = QTableWidget(0, 4)
        self.auto_result_table.setHorizontalHeaderLabels(["CVE", "尝试端口", "成功", "成功端口"])
        self.auto_result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.auto_result_table.setEditTriggers(QTableWidget.NoEditTriggers)
        summary_layout.addWidget(self.auto_result_table)
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        widget.setLayout(layout)
        return widget
    
    def start_auto_test(self):
        """开始自动化测试"""
        host_input = self.auto_url_input.text().strip()
        # 使用默认参数
        cmd = "whoami"
        fp_timeout = 3
        send_timeout = 10
        if not host_input:
            QMessageBox.warning(self, "警告", "请输入目标 IP 或 IP:端口 或 URL")
            return

        # 读取端口扫描复选框状态（若存在）
        try:
            do_port_scan = bool(self.auto_portscan_chk.isChecked())
        except Exception:
            do_port_scan = False

        # 解析自定义端口输入（若有）
        ports_list = None
        ports_text = ""
        try:
            ports_text = self.auto_ports_input.text().strip()
        except Exception:
            ports_text = ""

        if ports_text:
            try:
                if '-' in ports_text and ',' not in ports_text:
                    start, end = ports_text.split('-', 1)
                    ports_list = list(range(int(start.strip()), int(end.strip()) + 1))
                else:
                    ports_list = [int(p.strip()) for p in ports_text.split(',') if p.strip()]
            except Exception:
                QMessageBox.warning(self, "警告", "端口格式错误，请使用逗号分隔或范围（如 80,443 或 1-1024）")
                # 恢复为 None，让扫描使用默认常见端口集合
                ports_list = None

        # 端口超时
        try:
            port_timeout = self.auto_port_timeout_spin.value()
        except Exception:
            port_timeout = 2

        # 如果用户没有提供自定义端口，按复选框选择端口集合
        if not ports_text:
            try:
                if getattr(self, "auto_use_all_ports_chk", None) and self.auto_use_all_ports_chk.isChecked():
                    # 全量端口
                    ports_list = list(range(1, 65536))
                elif getattr(self, "auto_use_common_ports_chk", None) and self.auto_use_common_ports_chk.isChecked():
                    # 常用端口：传 None 让 scan_ports 使用 COMMON_PORTS
                    ports_list = None
                else:
                    ports_list = None
            except Exception:
                ports_list = None

        # 禁用按钮
        self.auto_test_btn.setEnabled(False)
        self.auto_test_btn.setText("测试中...")
        self.auto_result_text.clear()
        
        # 创建工作线程，传入端口扫描参数
        self.auto_worker = AutoTestWorker(host_input, cmd, fp_timeout, send_timeout,
                                         do_port_scan=do_port_scan, ports=ports_list, port_timeout=port_timeout)
        self.auto_worker.log_signal.connect(self.on_auto_test_log)
        self.auto_worker.detail_signal.connect(self.on_auto_test_detail)
        self.auto_worker.finished.connect(self.on_auto_test_finished)
        self.auto_worker.error.connect(self.on_auto_test_error)
        # 清空表格与日志
        try:
            self.auto_result_table.setRowCount(0)
        except Exception:
            pass
        self.auto_worker.start()
    
    def on_auto_test_log(self, msg):
        """自动化测试日志回调"""
        self.auto_result_text.append(msg)
        # 滚动到底部
        cursor = self.auto_result_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.auto_result_text.setTextCursor(cursor)
    
    def on_auto_test_finished(self, success_count, total_count):
        """自动化测试完成回调"""
        self.auto_test_btn.setEnabled(True)
        self.auto_test_btn.setText("开始自动化测试")
        
        self.auto_result_text.append("\n" + "=" * 60)
        self.auto_result_text.append("自动化测试完成")
        self.auto_result_text.append(f"成功执行: {success_count}/{total_count}")
        self.auto_result_text.append("=" * 60)
        
        if success_count > 0:
            QMessageBox.information(self, "完成", f"自动化测试完成\n成功执行: {success_count}/{total_count}")
        else:
            QMessageBox.warning(self, "完成", f"自动化测试完成，但所有Payload执行失败")
    
    def on_auto_test_error(self, error_msg):
        """自动化测试错误回调"""
        self.auto_test_btn.setEnabled(True)
        self.auto_test_btn.setText("开始自动化测试")
        self.auto_result_text.append(f"\n[!] 错误: {error_msg}")
        QMessageBox.critical(self, "错误", f"自动化测试失败: {error_msg}")

    def on_auto_test_detail(self, detail: dict):
        """收到单个 CVE 的执行详情并更新表格"""
        try:
            cve = detail.get("cve", "")
            executed_ports = detail.get("executed_ports", []) or []
            success = detail.get("success", False)
            success_port = detail.get("success_port", None)

            row = self.auto_result_table.rowCount()
            self.auto_result_table.insertRow(row)

            self.auto_result_table.setItem(row, 0, QTableWidgetItem(cve))
            self.auto_result_table.setItem(row, 1, QTableWidgetItem(", ".join(str(p) for p in executed_ports)))
            self.auto_result_table.setItem(row, 2, QTableWidgetItem("是" if success else "否"))
            self.auto_result_table.setItem(row, 3, QTableWidgetItem(str(success_port) if success_port else "-"))
        except Exception as e:
            # 同时输出到日志，避免静默失败
            self.auto_result_text.append(f"[!] 更新表格失败: {e}")

    def on_auto_portscan_toggled(self, checked: bool):
        """启用/禁用端口相关选项"""
        try:
            enabled = bool(checked)
            self.auto_ports_input.setEnabled(enabled)
            self.auto_port_timeout_spin.setEnabled(enabled)
            self.auto_use_all_ports_chk.setEnabled(enabled)
            self.auto_use_common_ports_chk.setEnabled(enabled)
            # 当禁用端口扫描时，清空表格的端口选择状态（保持默认行为）
            if not enabled:
                self.auto_ports_input.clear()
                self.auto_use_all_ports_chk.setChecked(False)
                self.auto_use_common_ports_chk.setChecked(True)
        except Exception:
            pass

    def on_auto_ports_option_changed(self, checked: bool):
        """处理全量/常用复选框互斥与自定义输入互斥逻辑"""
        try:
            # 如果用户选中全量端口，则取消常用端口选择，禁用自定义输入
            if self.auto_use_all_ports_chk.isChecked():
                self.auto_use_common_ports_chk.setChecked(False)
                self.auto_ports_input.setEnabled(False)
            elif self.auto_use_common_ports_chk.isChecked():
                self.auto_use_all_ports_chk.setChecked(False)
                self.auto_ports_input.setEnabled(False)
            else:
                # 两者都未选中，则允许自定义端口输入
                self.auto_ports_input.setEnabled(True)
        except Exception:
            pass

    def on_auto_ports_input_changed(self, text: str):
        """当自定义端口输入有内容时，取消全量/常用复选框的勾选"""
        try:
            txt = str(text).strip()
            if txt:
                # 清除其他复选框，优先使用自定义端口
                try:
                    self.auto_use_all_ports_chk.setChecked(False)
                    self.auto_use_common_ports_chk.setChecked(False)
                except Exception:
                    pass
            else:
                # 如果自定义输入变为空，恢复常用端口默认选中
                try:
                    if not self.auto_use_all_ports_chk.isChecked() and not self.auto_use_common_ports_chk.isChecked():
                        self.auto_use_common_ports_chk.setChecked(True)
                except Exception:
                    pass
        except Exception:
            pass
    
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

