#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复 poc_gui.py 中的中文标点符号编码问题
"""

# 读取文件
with open('poc_gui.py', 'r', encoding='utf-8') as f:
    content = f.read()

# 全角符号 -> 半角符号
content = content.replace('（', '(')
content = content.replace('）', ')')
content = content.replace('，', ',')
content = content.replace('：', ':')
content = content.replace('。', '.')
content = content.replace('；', ';')
content = content.replace('？', '?')
content = content.replace('！', '!')

# 写回文件
with open('poc_gui.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("修复完成！")
