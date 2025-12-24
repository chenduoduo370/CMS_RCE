#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Payload 发送模块

从原来的 poc_tool.py 中拆分出来，专门负责：
- 动态加载 payload 模块（payloads/xxx.py）
- 生成 payload 数据
- 实际发送 HTTP 请求
- 列出可用的 payload 模块
"""

import os
import sys
import json
import importlib
from typing import Optional

import requests


# 保持与原 poc_tool.py 中一致的目录获取方式
current_dir = os.path.dirname(os.path.abspath(__file__))


class PayloadManager:
    """Payload管理器 - 统一的payload操作接口"""

    def __init__(self, debug: bool = False) -> None:
        self.debug = debug
        self.current_dir = current_dir

    def _normalize_url(self, url: str, ip_port: str, headers: dict) -> str:
        """
        确保URL可直接请求。如果模块只提供了路径，自动补全协议和Host。
        """
        if url.startswith("http://") or url.startswith("https://"):
            return url

        host = headers.get("Host", ip_port)
        path = url if url.startswith("/") else f"/{url}"
        return f"http://{host}{path}"

    def load_payload_module(self, name: str, raise_on_error: bool = False):
        """动态加载payloads/下的模块
        
        Args:
            name: 模块名
            raise_on_error: 如果为True，出错时抛出异常而不是调用sys.exit
        """
        try:
            if self.debug:
                print(f"[DEBUG] 当前工作目录: {os.getcwd()}")
                print(f"[DEBUG] 脚本目录: {self.current_dir}")
                print(f"[DEBUG] 尝试导入: payloads.{name}")

            # 检查文件是否存在
            payload_file = os.path.join(self.current_dir, "payloads", f"{name}.py")
            if not os.path.exists(payload_file):
                msg = f"文件不存在: {payload_file}"
                print(f"[!] 错误: {msg}", file=sys.stderr, flush=True)
                if raise_on_error:
                    raise FileNotFoundError(msg)
                sys.exit(1)

            module = importlib.import_module(f"payloads.{name}")
            if not hasattr(module, "build"):
                raise Exception(f"模块 {name} 缺少 build(ip_port, cmd) 方法")

            if self.debug:
                print(f"[DEBUG] 模块加载成功: {module}")

            return module
        except ImportError as e:
            print(f"[!] 导入模块失败: {e}", file=sys.stderr, flush=True)
            if raise_on_error:
                raise
            if self.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)
        except FileNotFoundError:
            raise
        except Exception as e:
            print(f"[!] 加载模块失败: {e}", file=sys.stderr, flush=True)
            if raise_on_error:
                raise
            if self.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    def generate_payload(self, module_name: str, ip_port: str, cmd: str) -> Optional[dict]:
        """生成payload数据（不发送）"""
        try:
            if self.debug:
                print(f"[DEBUG] 调用 module.build('{ip_port}', '{cmd}')")

            module = self.load_payload_module(module_name)
            payload_data = module.build(ip_port, cmd)

            if self.debug:
                print(f"[DEBUG] build() 返回类型: {type(payload_data)}")

            if not isinstance(payload_data, dict):
                print(
                    f"[!] 错误: build() 方法返回的不是字典类型，而是: {type(payload_data)}",
                    file=sys.stderr,
                    flush=True,
                )
                return None

            # 检查必需的键
            required_keys = ["url", "headers"]
            for key in required_keys:
                if key not in payload_data:
                    print(
                        f"[!] 错误: payload_data 缺少必需的键 '{key}'",
                        file=sys.stderr,
                        flush=True,
                    )
                    print(
                        f"[!] payload_data 包含的键: {list(payload_data.keys())}",
                        file=sys.stderr,
                        flush=True,
                    )
                    return None

            return payload_data
        except Exception as e:
            print(f"[!] 生成payload时发生错误: {e}", file=sys.stderr, flush=True)
            if self.debug:
                import traceback
                traceback.print_exc()
            return None

    def show_payload(self, module_name: str, ip_port: str, cmd: str, show_json: bool = False) -> Optional[dict]:
        """显示payload的详细信息（不发送）"""
        print(f"\n{'='*60}", flush=True)
        print("Payload生成器", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"模块: {module_name}", flush=True)
        print(f"目标: {ip_port}", flush=True)
        print(f"命令: {cmd}", flush=True)
        print(f"{'='*60}\n", flush=True)

        print(f"[*] 加载模块: {module_name}", flush=True)
        payload_data = self.generate_payload(module_name, ip_port, cmd)

        if payload_data is None:
            return None

        print("[*] Payload生成成功!\n", flush=True)

        # 显示原始HTTP请求格式
        print("=" * 60, flush=True)
        print("[+] 原始 HTTP 请求:", flush=True)
        print("=" * 60, flush=True)

        http_method = payload_data.get("method", "POST")
        host_header = payload_data["headers"].get("Host", ip_port)

        # 提取URL路径
        url = payload_data["url"]
        if url.startswith("http://"):
            url_path = url.replace(f"http://{ip_port}", "").replace(f"http://{host_header}", "")
            if not url_path.startswith("/"):
                url_path = "/" + url_path
        elif url.startswith("https://"):
            url_path = url.replace(f"https://{ip_port}", "").replace(f"https://{host_header}", "")
            if not url_path.startswith("/"):
                url_path = "/" + url_path
        else:
            url_path = url if url.startswith("/") else "/" + url

        raw_request = [f"{http_method} {url_path} HTTP/1.1", f"Host: {host_header}"]

        # 追加其他 headers
        for header, value in payload_data["headers"].items():
            if header != "Host":
                raw_request.append(f"{header}: {value}")

        raw_request.append("")  # 空行分隔 headers 和 body

        data = payload_data.get("data", None)
        if data is not None:
            if isinstance(data, dict):
                raw_request.append(json.dumps(data, separators=(",", ":")))
            elif isinstance(data, str):
                raw_request.append(data)
            else:
                raw_request.append(str(data))

        for line in raw_request:
            print(line, flush=True)

        print("=" * 60, flush=True)

        if show_json:
            print("\n[+] Payload数据结构 (JSON):", flush=True)
            print(
                json.dumps(
                    {
                        "method": http_method,
                        "url": payload_data["url"],
                        "headers": payload_data["headers"],
                        "has_data": data is not None,
                        "data_type": type(data).__name__ if data is not None else None,
                    },
                    indent=2,
                    ensure_ascii=False,
                ),
                flush=True,
            )

        return payload_data

    def send_payload(self, module_name: str, ip_port: str, cmd: str, timeout: int = 10):
        """发送payload到目标"""
        print(f"\n{'='*60}", flush=True)
        print("发送Payload", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"模块: {module_name}", flush=True)
        print(f"目标: {ip_port}", flush=True)
        print(f"命令: {cmd}", flush=True)
        print(f"{'='*60}\n", flush=True)

        payload_data = self.generate_payload(module_name, ip_port, cmd)
        if payload_data is None:
            return None

        headers = payload_data["headers"]
        url = self._normalize_url(payload_data.get("url", ""), ip_port, headers)
        data = payload_data.get("data", None)
        method = payload_data.get("method", "POST").upper()

        print(f"[+] 使用 payload 模块: {module_name}", flush=True)
        print(f"[+] 发送到 URL: {url}", flush=True)
        print(f"[+] HTTP方法: {method}", flush=True)
        print(f"[+] 执行命令: {cmd}", flush=True)
        print(f"[+] 请求超时: {timeout}秒\n", flush=True)

        try:
            if method == "GET":
                response = requests.get(url, headers=headers, params=data, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, headers=headers, data=data, timeout=timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, data=data, timeout=timeout)
            else:
                response = requests.request(method, url, headers=headers, data=data, timeout=timeout)

            print("=" * 60, flush=True)
            print(f"[+] 响应状态码: {response.status_code}", flush=True)
            print("=" * 60, flush=True)
            print("响应头:", flush=True)
            for key, value in response.headers.items():
                print(f"  {key}: {value}", flush=True)
            print("\n响应体:", flush=True)
            print(response.text, flush=True)
            print("=" * 60, flush=True)

            return response
        except requests.exceptions.Timeout:
            print(f"[!] 请求超时（{timeout}秒）", file=sys.stderr, flush=True)
            return None
        except requests.exceptions.ConnectionError as e:
            print(f"[!] 连接错误: {e}", file=sys.stderr, flush=True)
            return None
        except Exception as e:
            print(f"[!] 发送请求时发生错误: {e}", file=sys.stderr, flush=True)
            if self.debug:
                import traceback
                traceback.print_exc()
            return None

    def send_payload_safe(self, module_name: str, ip_port: str, cmd: str, timeout: int = 10, log_callback=None):
        """发送payload到目标（安全版本，不会调用sys.exit，适用于自动化测试）
        
        Args:
            module_name: 模块名
            ip_port: 目标地址
            cmd: 执行命令
            timeout: 超时时间
            log_callback: 日志回调函数，用于GUI显示日志
        
        Returns:
            response对象，如果失败返回None
        """
        def log(msg):
            print(msg, flush=True)
            if log_callback:
                log_callback(msg)
        
        try:
            log(f"[*] 加载模块: {module_name}")
            module = self.load_payload_module(module_name, raise_on_error=True)
            log(f"[+] 模块加载成功")
            
            log(f"[*] 生成 Payload...")
            payload_data = module.build(ip_port, cmd)
            
            if not isinstance(payload_data, dict):
                log(f"[!] 错误: build() 方法返回的不是字典类型")
                return None
            
            headers = payload_data.get("headers", {})
            url = self._normalize_url(payload_data.get("url", ""), ip_port, headers)
            data = payload_data.get("data", None)
            method = payload_data.get("method", "POST").upper()
            
            log(f"[+] Payload 生成成功")
            log(f"    模块: {module_name}")
            log(f"    目标: {ip_port}")
            log(f"    URL: {url}")
            log(f"    方法: {method}")
            log(f"    命令: {cmd}")
            
            log(f"[*] 发送请求...")
            if method == "GET":
                response = requests.get(url, headers=headers, params=data, timeout=timeout)
            elif method == "POST":
                response = requests.post(url, headers=headers, data=data, timeout=timeout)
            elif method == "PUT":
                response = requests.put(url, headers=headers, data=data, timeout=timeout)
            else:
                response = requests.request(method, url, headers=headers, data=data, timeout=timeout)
            
            log(f"[+] 收到响应，状态码: {response.status_code}")
            log(f"[+] 响应体:")
            log(response.text)
            
            return response
        except FileNotFoundError as e:
            log(f"[!] 模块不存在: {e}")
            return None
        except requests.exceptions.Timeout:
            log(f"[!] 请求超时（{timeout}秒）")
            return None
        except requests.exceptions.ConnectionError as e:
            log(f"[!] 连接错误: {e}")
            return None
        except Exception as e:
            log(f"[!] 发送请求时发生错误: {e}")
            return None


def list_payloads() -> None:
    """列出所有可用的payload模块"""
    payloads_dir = os.path.join(current_dir, "payloads")
    print(f"\n{'='*60}", flush=True)
    print("可用的Payload模块", flush=True)
    print(f"{'='*60}", flush=True)

    if not os.path.exists(payloads_dir):
        print(f"[!] payloads目录不存在: {payloads_dir}", file=sys.stderr, flush=True)
        return

    payloads = []
    manager = PayloadManager(debug=False)

    for filename in os.listdir(payloads_dir):
        if not filename.endswith(".py"):
            continue
        if filename in ("__init__.py", "init.py"):
            continue
        if filename.startswith("__"):
            continue

        module_name = filename[:-3]
        try:
            module = manager.load_payload_module(module_name)
            if hasattr(module, "build"):
                payloads.append(module_name)
        except Exception:
            continue

    if not payloads:
        print("[!] 未找到任何payload模块", file=sys.stderr, flush=True)
        return

    for i, payload in enumerate(sorted(payloads), 1):
        print(f"  {i}. {payload}", flush=True)

    print(f"\n共 {len(payloads)} 个payload模块", flush=True)
    print("=" * 60, flush=True)


__all__ = ["PayloadManager", "list_payloads"]


