"""
HTTP数据包解析器 - 解析HTTP请求并生成CVE脚本
"""

import re
from typing import Dict, Optional


def parse_http_packet(packet: str) -> Dict:
    """
    解析HTTP请求数据包
    
    Args:
        packet: HTTP请求原始字符串
    
    Returns:
        包含method, url, headers, body等信息的字典
    """
    lines = packet.split('\n')
    
    # 寻找首个请求行（允许前面有日志/空行/BOM）
    request_idx = None
    method = ""
    path = ""
    for i, raw in enumerate(lines):
        request_line = raw.strip().lstrip('\ufeff').lstrip('\ufffe')
        if not request_line:
            continue
        method_match = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+?)\s+HTTP', request_line, re.IGNORECASE)
        if method_match:
            method = method_match.group(1).upper()
            path = method_match.group(2).strip()
            request_idx = i
            break
    if request_idx is None:
        raise ValueError("无法解析HTTP请求行")
    
    # 解析headers（遇到首个空行即认为headers结束）
    headers = {}
    body_start = len(lines)
    
    for i, line in enumerate(lines[request_idx + 1:], request_idx + 1):
        line_stripped = line.strip()
        
        # 如果遇到空行
        if not line_stripped:
            body_start = i + 1
            break
        
        # 解析header
        if ':' in line_stripped:
            key, value = line_stripped.split(':', 1)
            headers[key.strip()] = value.strip()
    
    # 解析body（如果有），若遇到分隔符(====)或日志行则提前结束
    body_lines = []
    if body_start < len(lines):
        for line in lines[body_start:]:
            if re.match(r'^\s*={4,}', line):
                break
            body_lines.append(line)
    body = '\n'.join(body_lines).strip()
    
    # 提取Host
    host = headers.get('Host', '')
    
    # 构建完整URL
    if path.startswith('http'):
        full_url = path
    elif host:
        scheme = 'https' if 'https' in headers.get('Referer', '') else 'http'
        full_url = f"{scheme}://{host}{path}"
    else:
        full_url = path
    
    return {
        'method': method,
        'path': path,
        'url': full_url,
        'host': host,
        'headers': headers,
        'body': body
    }


def generate_cve_script_from_packet(packet: str, cve_id: str = "CVE-XXXX-XXXX",
                                   description: str = "[待补充]",
                                   affected_versions: str = "[待补充]",
                                   references: str = "[待补充]") -> str:
    """
    根据HTTP数据包生成CVE脚本
    
    Args:
        packet: HTTP请求数据包字符串
        cve_id: CVE编号
        description: 漏洞描述
        affected_versions: 受影响版本
        references: 参考链接
    
    Returns:
        生成的Python脚本代码
    """
    try:
        parsed = parse_http_packet(packet)
    except Exception as e:
        return f"# 错误: 无法解析HTTP数据包 - {str(e)}"
    
    method = parsed['method']
    path = parsed['path']
    headers = parsed['headers']
    body = parsed['body']
    host = parsed['host']
    
    # 初始化处理后的body
    body_processed = body

    # 构造精简的 packet_payload（请求行 + 头 + 体），Host 使用占位 ip_port
    packet_lines = [f"{method} {path} HTTP/1.1"]
    packet_lines.append("Host: {ip_port}")
    for k, v in headers.items():
        if k.lower() in ('host', 'content-length'):
            continue
        packet_lines.append(f"{k}: {v}")
    packet_lines.append("")  # 空行分隔
    if body_processed:
        packet_lines.append(body_processed)
    minimal_packet = "\n".join(packet_lines)
    # 转义数据包中的特殊字符
    escaped_packet = minimal_packet.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
    
    # 开始构建脚本
    script = f'''# {cve_id}.py
# 描述: {description}
# 受影响版本: {affected_versions}
# 参考: {references}

import json

def build(ip_port: str, cmd: str):
    """
    构建漏洞利用请求
    
    Args:
        ip_port: 目标IP和端口，格式如 "192.168.1.1:80" 或 "example.com"
        cmd: 要执行的命令
    """
    # 计算命令长度
    cmd_len = len(cmd)
    
    # 构建URL
    url = "{path}"
    
    # 原始数据包载荷
    packet_payload = """{escaped_packet}
"""
    
    # 构建请求头
    headers = {{
'''
    
    # 添加headers
    for key, value in headers.items():
        if key.lower() == 'host':
            script += f'        "{key}": ip_port,\n'
        elif key.lower() == 'content-length':
            # 避免固定长度，由 requests 自动计算
            continue
        else:
            # 转义引号和反斜杠
            escaped_value = value.replace('\\', '\\\\').replace('"', '\\"')
            script += f'        "{key}": "{escaped_value}",\n'
    
    script += '''    }
    
    # 构建请求体（如果有）
'''
    
    if method.upper() == 'GET':
        script += '''    data = None
'''
    else:
        if body:
            content_type = headers.get('Content-Type', '').lower()
            if 'application/x-www-form-urlencoded' in content_type:
                # 表单编码：如果原始body有&则直接使用，否则按行解析 k:v 组装为 key=value&...
                if '&' in body:
                    form_line = body.strip()
                else:
                    kv_pairs = []
                    for ln in body.splitlines():
                        ln = ln.strip().strip(',').strip()
                        if not ln or ':' not in ln:
                            continue
                        k, v = ln.split(':', 1)
                        k = k.strip().strip('"').strip("'")
                        v = v.strip().strip('"').strip("'")
                        if k:
                            kv_pairs.append(f"{k}={v}")
                    form_line = '&'.join(kv_pairs)
                # 替换命令参数
                form_line = re.sub(r'mail\\[#markup\\]=[^&]*', 'mail[#markup]={cmd}', form_line)
                form_line = form_line.replace('whaomi', '{cmd}').replace('whoami', '{cmd}')
                body_processed = form_line
                script += f'''    data = "{body_processed}"
'''
            else:
                # 保留原始body，处理占位符
                body_processed = body.replace("whaomi", "{cmd}").replace("whoami", "{cmd}")
                body_pretty = body_processed
                # 若body是JSON对象，转换为逐行键值形式，方便对比原始示例
                try:
                    import json as _json
                    obj = _json.loads(body_processed)
                    if isinstance(obj, dict):
                        lines = []
                        items = list(obj.items())
                        for idx, (k, v) in enumerate(items):
                            comma = "," if idx < len(items) - 1 else ""
                            lines.append(f'"{k}": "{v}"{comma}')
                        body_pretty = "\n".join(lines)
                except Exception:
                    pass

                escaped_body = body_pretty.replace('\\', '\\\\').replace('"""', '\\"\\"\\"')
                script += f'''    # 构建请求体模板
    # 注意：按需替换IP端口和命令
    # body = body.replace('{ip_port}', ip_port)
    # body = body.replace('s:2:\\"id\\"', f's:{{cmd_len}}:\\"{{cmd}}\\"')
    
    data = """{escaped_body}
"""
    # 替换IP端口和命令
    data = data.replace('{{ip_port}}', ip_port)
    data = data.replace('{{cmd}}', cmd)
    data = data.replace('s:2:\\\\"id\\\\"', f's:{{cmd_len}}:\\\\"{{cmd}}\\\\"')
'''
        else:
            script += '''    data = None
'''
    
    script += f'''
    return {{
        "method": "{method}",
        "url": f"http://{{ip_port}}{{url}}",
        "headers": headers,
        "data": data
    }}
'''
    
    return script


def main():
    """主函数：交互式生成CVE脚本"""
    print("=" * 60)
    print("HTTP数据包解析器 - CVE脚本生成工具")
    print("=" * 60)
    
    print("\n请粘贴HTTP请求数据包（输入完成后按Ctrl+Z然后回车，或输入空行结束）:")
    print("-" * 60)
    
    lines = []
    try:
        while True:
            line = input()
            if line.strip() == "" and lines:
                # 连续两个空行表示结束
                break
            lines.append(line)
    except EOFError:
        pass
    
    packet = '\n'.join(lines)
    
    if not packet.strip():
        print("错误: 数据包内容为空!")
        return
    
    cve_id = input("\n请输入CVE编号 (例如: CVE-2019-6340): ").strip() or "CVE-XXXX-XXXX"
    description = input("漏洞描述 (可选): ").strip() or "[待补充]"
    affected_versions = input("受影响版本 (可选): ").strip() or "[待补充]"
    references = input("参考链接 (可选): ").strip() or "[待补充]"
    
    # 生成脚本
    print("\n正在解析数据包并生成脚本...")
    script = generate_cve_script_from_packet(
        packet=packet,
        cve_id=cve_id,
        description=description,
        affected_versions=affected_versions,
        references=references
    )
    
    print("\n生成的脚本:")
    print("=" * 60)
    print(script)
    print("=" * 60)
    
    # 询问是否保存
    save = input("\n是否保存到文件? (y/n): ").strip().lower()
    if save == 'y':
        filename = cve_id.replace("-", "_") + ".py"
        output_path = f"payloads/{filename}"
        
        import os
        os.makedirs("payloads", exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(script)
        print(f"脚本已保存到: {output_path}")


if __name__ == "__main__":
    main()


