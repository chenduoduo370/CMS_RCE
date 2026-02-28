#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AI 控制台功能测试脚本
验证 QianwenWorker 和相关配置的正确性
"""

import sys
import os
import json
from pathlib import Path

# 添加项目根目录到 Python 路径
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_config():
    """测试配置模块"""
    print("\n" + "="*60)
    print("测试 1: Config 模块")
    print("="*60)

    from src.config import Config

    print(f"[OK] QIANWEN_BASE_URL: {Config.QIANWEN_BASE_URL}")
    print(f"[OK] QIANWEN_MODELS: {Config.QIANWEN_MODELS}")
    print(f"[OK] QIANWEN_DEFAULT_MODEL: {Config.QIANWEN_DEFAULT_MODEL}")
    print(f"[OK] AI_CONFIG_FILE: {Config.AI_CONFIG_FILE}")

    ai_config_path = Config.get_ai_config_path()
    print(f"[OK] AI 配置文件路径: {ai_config_path}")

    return True

def test_qianwen_worker():
    """测试 QianwenWorker 类"""
    print("\n" + "="*60)
    print("测试 2: QianwenWorker 类")
    print("="*60)

    from src.gui.workers import QianwenWorker

    print(f"[OK] QianwenWorker 类成功导入")
    print(f"[OK] SYSTEM_PROMPT 长度: {len(QianwenWorker.SYSTEM_PROMPT)} 字符")
    print(f"[OK] 可用信号:")
    print(f"     - token_signal: 流式 token")
    print(f"     - finished: 对话完成")
    print(f"     - error: 错误消息")

    # 测试初始化（不启动线程）
    test_messages = [
        {"role": "system", "content": "test"},
        {"role": "user", "content": "hello"}
    ]

    worker = QianwenWorker(
        api_key="sk-test",
        model="qwen-plus",
        messages=test_messages,
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
    )

    print(f"[OK] QianwenWorker 实例化成功")
    print(f"     - api_key: sk-***")
    print(f"     - model: qwen-plus")
    print(f"     - messages: {len(test_messages)} 条")
    print(f"     - _stop_flag: {worker._stop_flag}")

    return True

def test_ai_config_persistence():
    """测试 AI 配置持久化"""
    print("\n" + "="*60)
    print("测试 3: AI 配置文件持久化")
    print("="*60)

    from src.config import Config

    ai_config_path = Config.get_ai_config_path()

    # 测试保存
    test_data = {
        "api_key": "sk-test-key-12345",
        "model": "qwen-turbo"
    }

    try:
        with open(ai_config_path, "w", encoding="utf-8") as f:
            json.dump(test_data, f, ensure_ascii=False, indent=2)
        print(f"[OK] 配置文件写入成功: {ai_config_path}")
    except Exception as e:
        print(f"[ERROR] 配置文件写入失败: {e}")
        return False

    # 测试读取
    try:
        with open(ai_config_path, "r", encoding="utf-8") as f:
            loaded_data = json.load(f)
        print(f"[OK] 配置文件读取成功")
        print(f"     - api_key: {loaded_data.get('api_key', 'N/A')}")
        print(f"     - model: {loaded_data.get('model', 'N/A')}")
    except Exception as e:
        print(f"[ERROR] 配置文件读取失败: {e}")
        return False

    # 验证 is_llm_configured()
    is_configured = Config.is_llm_configured()
    print(f"[OK] is_llm_configured() 返回: {is_configured}")

    # 清理测试文件
    try:
        ai_config_path.unlink()
        print(f"[OK] 测试配置文件已清理")
    except Exception as e:
        print(f"[WARN] 清理测试文件失败 (可忽略): {e}")

    return True

def test_imports():
    """测试所有关键导入"""
    print("\n" + "="*60)
    print("测试 4: 关键模块导入")
    print("="*60)

    try:
        from PyQt5.QtWidgets import QApplication, QMainWindow
        print("[OK] PyQt5.QtWidgets 导入成功")
    except Exception as e:
        print(f"[ERROR] PyQt5.QtWidgets 导入失败: {e}")
        return False

    try:
        from PyQt5.QtCore import QThread, pyqtSignal
        print("[OK] PyQt5.QtCore 导入成功")
    except Exception as e:
        print(f"[ERROR] PyQt5.QtCore 导入失败: {e}")
        return False

    try:
        from PyQt5.QtGui import QFont, QTextCursor
        print("[OK] PyQt5.QtGui 导入成功")
    except Exception as e:
        print(f"[ERROR] PyQt5.QtGui 导入失败: {e}")
        return False

    try:
        from src.gui.workers import QianwenWorker
        print("[OK] src.gui.workers.QianwenWorker 导入成功")
    except Exception as e:
        print(f"[ERROR] src.gui.workers.QianwenWorker 导入失败: {e}")
        return False

    try:
        from src.config import Config
        print("[OK] src.config.Config 导入成功")
    except Exception as e:
        print(f"[ERROR] src.config.Config 导入失败: {e}")
        return False

    return True

def main():
    """运行所有测试"""
    print("\n")
    print("="*60)
    print("        千问 AI 控制台 - 功能验证测试")
    print("="*60)

    all_passed = True

    all_passed = test_imports() and all_passed
    all_passed = test_config() and all_passed
    all_passed = test_qianwen_worker() and all_passed
    all_passed = test_ai_config_persistence() and all_passed

    print("\n" + "="*60)
    if all_passed:
        print("[SUCCESS] 所有测试通过! AI 控制台已准备就绪。")
        print("\n使用说明:")
        print("1. 运行 'python poc_gui.py' 启动 GUI")
        print("2. 进入 'AI 控制台' 标签页")
        print("3. 输入阿里云千问 API Key (sk-...)")
        print("4. 选择模型 (qwen-plus 或 qwen-turbo)")
        print("5. 点击'保存配置'或'发送'开始对话")
        print("6. 支持 Ctrl+Enter 快捷键发送消息")
    else:
        print("[FAILED] 某些测试失败，请检查上面的错误信息。")
        return 1

    print("="*60 + "\n")
    return 0

if __name__ == "__main__":
    exit(main())
