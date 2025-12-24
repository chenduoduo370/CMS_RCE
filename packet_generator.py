#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP 数据包解析与 Payload 模板生成模块

从原来的 poc_tool.py 中拆分出来，专门负责：
- 读取 HTTP 报文字符串或文件
- 解析方法 / 路径 / 头部 / 请求体
- 生成 payload 模板文件（payloads/xxx.py）
"""

import os
import sys
from typing import Optional, Dict

try:
    from http_packet_parser import parse_http_packet
except ImportError:
    parse_http_packet = None  # type: ignore


current_dir = os.path.dirname(os.path.abspath(__file__))


def _escape_body_for_python_string(body: str) -> str:
    """
    对 body 内容进行转义，使其可以安全地放在 Python 普通字符串中。
    使用 repr() 自动处理所有转义，然后去掉首尾的引号。
    """
    if not body:
        return ""

    escaped = repr(body)

    if (escaped.startswith('"') and escaped.endswith('"')) or (
        escaped.startswith("'") and escaped.endswith("'")
    ):
        escaped = escaped[1:-1]

    if '"""' in escaped and '\\"\\"\\"' not in escaped:
        escaped = escaped.replace('"""', '\\"\\"\\"')

    return escaped


def _write_payload_stub(parsed: Dict, cve_id: str, output_dir: Optional[str] = None, gui_mode: bool = False) -> Optional[str]:
    """
    根据拆解结果生成一个 payload 模板文件，便于后续手工微调。
    """
    try:
        if output_dir is None:
            output_dir = os.path.join(current_dir, "payloads")
        os.makedirs(output_dir, exist_ok=True)

        filename = cve_id.replace("-", "_") + ".py"
        output_path = os.path.join(output_dir, filename)

        method = parsed.get("method", "POST")
        path = parsed.get("path", "/")
        headers = parsed.get("headers", {}) or {}
        body_raw = parsed.get("body", "")

        if path.startswith("http://") or path.startswith("https://"):
            from urllib.parse import urlparse

            parsed_url = urlparse(path)
            path = parsed_url.path
            if parsed_url.query:
                path += "?" + parsed_url.query
            if parsed_url.fragment:
                path += "#" + parsed_url.fragment

        if not path.startswith("/"):
            path = "/" + path

        path = path.replace("{ip_port}", "").replace("http://", "").replace("https://", "")

        body_escaped = _escape_body_for_python_string(body_raw)

        # 从原始请求头中提取 Content-Type（如果有），否则给一个合理的默认值
        content_type = headers.get("Content-Type") or headers.get("content-type") or "application/hal+json"

        template = f'''# {cve_id}
import json

def build(ip_port: str, cmd: str):
    url = "{path}"

    headers = {{
        "Host": ip_port,  # 使用实际目标主机
        "Content-Type": "{content_type}",
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


def generate_from_packet(
    packet: str,
    cve_id: str,
    save: bool = False,
    output_dir: Optional[str] = None,
    gui_mode: bool = False,
) -> Dict:
    """
    从HTTP数据包拆解关键信息，便于后续手工替换/改造。
    仅输出拆解结果和简单提示，不直接生成脚本，保持通用性。
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

    def _fallback_parse(raw: str) -> Dict:
        """简单拆包：方法、路径、头、体。"""
        lines = raw.replace("\r\n", "\n").split("\n")
        method, path, proto = "UNKNOWN", "/", "HTTP/1.1"
        headers: Dict[str, str] = {}
        body_lines = []
        in_body = False
        for idx, line in enumerate(lines):
            if idx == 0 and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    method = parts[0]
                    path = parts[1]
                    proto = parts[2] if len(parts) > 2 else proto

                    if path.startswith("http://") or path.startswith("https://"):
                        from urllib.parse import urlparse

                        parsed_url = urlparse(path)
                        path = parsed_url.path
                        if parsed_url.query:
                            path += "?" + parsed_url.query
                        if parsed_url.fragment:
                            path += "#" + parsed_url.fragment

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
        parsed: Optional[Dict] = None
        if parse_http_packet:
            parsed = parse_http_packet(packet)
        if not parsed:
            parsed = _fallback_parse(packet)

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

        output_lines.append("\n提示：")
        output_lines.append("- 将敏感字段（Host、Cookie、Token、Session、路径、命令参数等）替换为目标环境值")
        output_lines.append("- 对 body 中的命令/文件名/参数做最小改动，保留结构")
        output_lines.append("- 如果需要动态插值，可把待替换字段改成占位符，例如 {CMD}、{PATH}")
        output_lines.append("- 发送前可用 show/send 子命令加载改造后的模块进行验证")

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

        result = parsed.copy()
        result["_output_text"] = "\n".join(output_lines)
        return result
    except Exception as e:
        error_msg = f"[!] 拆解数据包时发生错误: {e}"
        if not gui_mode:
            print(error_msg, file=sys.stderr, flush=True)
            if hasattr(e, "__traceback__"):
                import traceback

                traceback.print_exc()
        return {"_output_text": error_msg, "_error": True}


def read_packet_file(file_path: str) -> str:
    """
    读取数据包文件，兼容不同编码/二进制内容。
    优先尝试utf-8，其次latin-1，最终使用替换策略避免解码失败。
    """
    with open(file_path, "rb") as f:
        raw = f.read()

    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass

    try:
        return raw.decode("latin-1")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace")


__all__ = ["generate_from_packet", "read_packet_file"]


