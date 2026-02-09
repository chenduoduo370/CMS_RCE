#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import codecs

# 读取原始文件内容（使用UTF-8编码）
with open('poc_gui.py', 'rb') as f:
    raw_content = f.read()

# 检测并修复BOM问题
if raw_content.startswith(codecs.BOM_UTF8):
    content = raw_content.decode('utf-8-sig')
else:
    content = raw_content.decode('utf-8')

# 替换所有全角符号为半角符号
replacements = [
    ('（', '('),
    ('）', ')'),
    ('，', ','),
    ('：', ':'),
    ('。', '.'),
    ('；', ';'),
    ('？', '?'),
    ('！', '!'),
]

for old, new in replacements:
    content = content.replace(old, new)

# 写回文件（不带BOM）
with open('poc_gui.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("Fixed!")

