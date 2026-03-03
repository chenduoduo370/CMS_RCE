#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证 AI 自动化测试流程完整性
检查：
1. TriggerHandler 能正确解析 AUTOTEST 标记
2. 参数验证逻辑正确
3. 信号连接正确
"""

import json
import sys
import os

# 强制使用 UTF-8 输出
if sys.stdout.encoding != 'utf-8':
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

def test_trigger_handler():
    """测试 TriggerHandler 解析"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] TriggerHandler - 解析 AUTOTEST 标记")
    print("="*60)

    # 测试用例 1：基本参数
    response1 = """
    好的，我已确认参数。现在开始渗透测试：
    ##AUTOTEST##{"host":"192.168.1.1","cmd":"whoami","do_port_scan":false,"ports":[80,443],"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response1)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert params['host'] == '192.168.1.1', f"host 错误: {params.get('host')}"
    assert params['ports'] == [80, 443], f"ports 错误: {params.get('ports')}"
    assert params['do_port_scan'] == False, f"do_port_scan 错误: {params.get('do_port_scan')}"
    print("[OK] 测试用例 1（指定端口）: 通过")

    # 测试用例 2：启用端口扫描
    response2 = """
    ##AUTOTEST##{"host":"example.com","cmd":"whoami","do_port_scan":true,"ports":null,"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response2)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert params['host'] == 'example.com', f"host 错误: {params.get('host')}"
    assert params['do_port_scan'] == True, f"do_port_scan 错误: {params.get('do_port_scan')}"
    assert params['ports'] is None, f"ports 应为 None: {params.get('ports')}"
    print("[OK] 测试用例 2（端口扫描）: 通过")

    # 测试用例 3：端口范围转换为数组
    response3 = """
    ##AUTOTEST##{"host":"10.0.0.1","cmd":"whoami","do_port_scan":false,"ports":[1,2,3,4,5],"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response3)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert len(params['ports']) == 5, f"ports 长度错误: {len(params['ports'])}"
    print("[OK] 测试用例 3（多端口）: 通过")


def test_parameter_validation():
    """测试参数验证"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] TriggerHandler - 参数验证")
    print("="*60)

    # 测试有效参数
    valid_params = {
        "host": "192.168.1.1",
        "cmd": "whoami",
        "do_port_scan": False,
        "ports": [80, 443],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', valid_params)
    assert is_valid, f"有效参数验证失败: {error}"
    print("[OK] 有效参数验证: 通过")

    # 测试缺少 host
    invalid_params1 = {
        "cmd": "whoami",
        "do_port_scan": False,
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params1)
    assert not is_valid, "应该拒绝缺少 host 的参数"
    assert "host" in error, f"错误信息应包含 'host': {error}"
    print("[OK] 缺少 host 检测: 通过")

    # 测试缺少 cmd
    invalid_params2 = {
        "host": "192.168.1.1",
        "do_port_scan": False,
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params2)
    assert not is_valid, "应该拒绝缺少 cmd 的参数"
    assert "cmd" in error, f"错误信息应包含 'cmd': {error}"
    print("[OK] 缺少 cmd 检测: 通过")

    # 测试无效的 do_port_scan
    invalid_params3 = {
        "host": "192.168.1.1",
        "cmd": "whoami",
        "do_port_scan": "yes",  # 应该是 bool
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params3)
    assert not is_valid, "应该拒绝非布尔值的 do_port_scan"
    print("[OK] do_port_scan 类型检查: 通过")


def test_signal_connections():
    """测试信号连接是否正确"""
    from src.gui.workers import AutoTestWorker

    print("\n" + "="*60)
    print("[TEST] AutoTestWorker - 信号连接")
    print("="*60)

    worker = AutoTestWorker(
        url="192.168.1.1",
        cmd="whoami",
        fp_timeout=3,
        send_timeout=10,
        do_port_scan=False,
        ports=[80],
        port_timeout=2,
        verbose=False
    )

    # 检查信号定义
    assert hasattr(worker, 'log_signal'), "缺少 log_signal"
    assert hasattr(worker, 'detail_signal'), "缺少 detail_signal"
    assert hasattr(worker, 'finished'), "缺少 finished"
    assert hasattr(worker, 'error'), "缺少 error"

    print("[OK] 所有信号都已定义")

    # 检查参数存储
    assert worker.url == "192.168.1.1", f"url 存储错误: {worker.url}"
    assert worker.cmd == "whoami", f"cmd 存储错误: {worker.cmd}"
    assert worker.do_port_scan == False, f"do_port_scan 存储错误: {worker.do_port_scan}"
    assert worker.ports == [80], f"ports 存储错误: {worker.ports}"
    assert worker.port_timeout == 2, f"port_timeout 存储错误: {worker.port_timeout}"

    print("[OK] 所有参数都正确存储")


def test_workflow_integration():
    """测试完整工作流"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] 完整工作流集成")
    print("="*60)

    # 模拟 AI 响应
    ai_response = """
根据您的需求，我已准备好进行自动化渗透测试。测试参数如下：
- 目标: 192.168.1.1
- 命令: whoami
- 端口: 80, 443
- 启用端口扫描: 否

现在开始执行测试：
##AUTOTEST##{"host":"192.168.1.1","cmd":"whoami","do_port_scan":false,"ports":[80,443],"port_timeout":2}##END##
    """

    # 步骤 1: 检测标记
    trigger_type, params = TriggerHandler.detect_trigger(ai_response)
    assert trigger_type == 'autotest', f"标记检测失败: {trigger_type}"
    print("[OK] 步骤 1 - 标记检测: 通过")

    # 步骤 2: 验证参数
    is_valid, error = TriggerHandler.validate_params(trigger_type, params)
    assert is_valid, f"参数验证失败: {error}"
    print("[OK] 步骤 2 - 参数验证: 通过")

    # 步骤 3: 创建 Worker（不启动）
    from src.gui.workers import AutoTestWorker
    worker = AutoTestWorker(
        url=params['host'],
        cmd=params['cmd'],
        fp_timeout=3,
        send_timeout=10,
        do_port_scan=params['do_port_scan'],
        ports=params['ports'],
        port_timeout=params['port_timeout'],
        verbose=False
    )
    print("[OK] 步骤 3 - Worker 创建: 通过")

    # 步骤 4: 验证参数传递
    assert worker.url == params['host'], "参数传递失败: url"
    assert worker.cmd == params['cmd'], "参数传递失败: cmd"
    assert worker.do_port_scan == params['do_port_scan'], "参数传递失败: do_port_scan"
    assert worker.ports == params['ports'], "参数传递失败: ports"
    print("[OK] 步骤 4 - 参数传递验证: 通过")

    print("\n[OK] 完整工作流集成测试: 通过")


def main():
    print("\n" + "="*60)
    print("AI 自动化测试流程验证")
    print("="*60)

    try:
        # 测试 1: TriggerHandler 解析
        test_trigger_handler()

        # 测试 2: 参数验证
        test_parameter_validation()

        # 测试 3: 信号连接
        test_signal_connections()

        # 测试 4: 完整工作流
        test_workflow_integration()

        print("\n" + "="*60)
        print("[PASS] 所有测试通过！")
        print("="*60)
        return 0

    except AssertionError as e:
        print(f"\n[FAIL] 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] 意外错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
    """测试 TriggerHandler 解析"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] TriggerHandler - 解析 AUTOTEST 标记")
    print("="*60)

    # 测试用例 1：基本参数
    response1 = """
    好的，我已确认参数。现在开始渗透测试：
    ##AUTOTEST##{"host":"192.168.1.1","cmd":"whoami","do_port_scan":false,"ports":[80,443],"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response1)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert params['host'] == '192.168.1.1', f"host 错误: {params.get('host')}"
    assert params['ports'] == [80, 443], f"ports 错误: {params.get('ports')}"
    assert params['do_port_scan'] == False, f"do_port_scan 错误: {params.get('do_port_scan')}"
    print("✓ 测试用例 1（指定端口）: 通过")

    # 测试用例 2：启用端口扫描
    response2 = """
    ##AUTOTEST##{"host":"example.com","cmd":"whoami","do_port_scan":true,"ports":null,"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response2)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert params['host'] == 'example.com', f"host 错误: {params.get('host')}"
    assert params['do_port_scan'] == True, f"do_port_scan 错误: {params.get('do_port_scan')}"
    assert params['ports'] is None, f"ports 应为 None: {params.get('ports')}"
    print("✓ 测试用例 2（端口扫描）: 通过")

    # 测试用例 3：端口范围转换为数组
    response3 = """
    ##AUTOTEST##{"host":"10.0.0.1","cmd":"whoami","do_port_scan":false,"ports":[1,2,3,4,5],"port_timeout":2}##END##
    """

    trigger_type, params = TriggerHandler.detect_trigger(response3)
    assert trigger_type == 'autotest', f"期望 'autotest'，得到 '{trigger_type}'"
    assert len(params['ports']) == 5, f"ports 长度错误: {len(params['ports'])}"
    print("✓ 测试用例 3（多端口）: 通过")


def test_parameter_validation():
    """测试参数验证"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] TriggerHandler - 参数验证")
    print("="*60)

    # 测试有效参数
    valid_params = {
        "host": "192.168.1.1",
        "cmd": "whoami",
        "do_port_scan": False,
        "ports": [80, 443],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', valid_params)
    assert is_valid, f"有效参数验证失败: {error}"
    print("✓ 有效参数验证: 通过")

    # 测试缺少 host
    invalid_params1 = {
        "cmd": "whoami",
        "do_port_scan": False,
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params1)
    assert not is_valid, "应该拒绝缺少 host 的参数"
    assert "host" in error, f"错误信息应包含 'host': {error}"
    print("✓ 缺少 host 检测: 通过")

    # 测试缺少 cmd
    invalid_params2 = {
        "host": "192.168.1.1",
        "do_port_scan": False,
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params2)
    assert not is_valid, "应该拒绝缺少 cmd 的参数"
    assert "cmd" in error, f"错误信息应包含 'cmd': {error}"
    print("✓ 缺少 cmd 检测: 通过")

    # 测试无效的 do_port_scan
    invalid_params3 = {
        "host": "192.168.1.1",
        "cmd": "whoami",
        "do_port_scan": "yes",  # 应该是 bool
        "ports": [80],
        "port_timeout": 2
    }

    is_valid, error = TriggerHandler.validate_params('autotest', invalid_params3)
    assert not is_valid, "应该拒绝非布尔值的 do_port_scan"
    print("✓ do_port_scan 类型检查: 通过")


def test_signal_connections():
    """测试信号连接是否正确"""
    from src.gui.workers import AutoTestWorker

    print("\n" + "="*60)
    print("[TEST] AutoTestWorker - 信号连接")
    print("="*60)

    worker = AutoTestWorker(
        url="192.168.1.1",
        cmd="whoami",
        fp_timeout=3,
        send_timeout=10,
        do_port_scan=False,
        ports=[80],
        port_timeout=2,
        verbose=False
    )

    # 检查信号定义
    assert hasattr(worker, 'log_signal'), "缺少 log_signal"
    assert hasattr(worker, 'detail_signal'), "缺少 detail_signal"
    assert hasattr(worker, 'finished'), "缺少 finished"
    assert hasattr(worker, 'error'), "缺少 error"

    print("✓ 所有信号都已定义")

    # 检查参数存储
    assert worker.url == "192.168.1.1", f"url 存储错误: {worker.url}"
    assert worker.cmd == "whoami", f"cmd 存储错误: {worker.cmd}"
    assert worker.do_port_scan == False, f"do_port_scan 存储错误: {worker.do_port_scan}"
    assert worker.ports == [80], f"ports 存储错误: {worker.ports}"
    assert worker.port_timeout == 2, f"port_timeout 存储错误: {worker.port_timeout}"

    print("✓ 所有参数都正确存储")


def test_workflow_integration():
    """测试完整工作流"""
    from src.ai.trigger_handler import TriggerHandler

    print("\n" + "="*60)
    print("[TEST] 完整工作流集成")
    print("="*60)

    # 模拟 AI 响应
    ai_response = """
根据您的需求，我已准备好进行自动化渗透测试。测试参数如下：
- 目标: 192.168.1.1
- 命令: whoami
- 端口: 80, 443
- 启用端口扫描: 否

现在开始执行测试：
##AUTOTEST##{"host":"192.168.1.1","cmd":"whoami","do_port_scan":false,"ports":[80,443],"port_timeout":2}##END##
    """

    # 步骤 1: 检测标记
    trigger_type, params = TriggerHandler.detect_trigger(ai_response)
    assert trigger_type == 'autotest', f"标记检测失败: {trigger_type}"
    print("✓ 步骤 1 - 标记检测: 通过")

    # 步骤 2: 验证参数
    is_valid, error = TriggerHandler.validate_params(trigger_type, params)
    assert is_valid, f"参数验证失败: {error}"
    print("✓ 步骤 2 - 参数验证: 通过")

    # 步骤 3: 创建 Worker（不启动）
    from src.gui.workers import AutoTestWorker
    worker = AutoTestWorker(
        url=params['host'],
        cmd=params['cmd'],
        fp_timeout=3,
        send_timeout=10,
        do_port_scan=params['do_port_scan'],
        ports=params['ports'],
        port_timeout=params['port_timeout'],
        verbose=False
    )
    print("✓ 步骤 3 - Worker 创建: 通过")

    # 步骤 4: 验证参数传递
    assert worker.url == params['host'], "参数传递失败: url"
    assert worker.cmd == params['cmd'], "参数传递失败: cmd"
    assert worker.do_port_scan == params['do_port_scan'], "参数传递失败: do_port_scan"
    assert worker.ports == params['ports'], "参数传递失败: ports"
    print("✓ 步骤 4 - 参数传递验证: 通过")

    print("\n✓ 完整工作流集成测试: 通过")


def main():
    print("\n" + "="*60)
    print("AI 自动化测试流程验证")
    print("="*60)

    try:
        # 测试 1: TriggerHandler 解析
        test_trigger_handler()

        # 测试 2: 参数验证
        test_parameter_validation()

        # 测试 3: 信号连接
        test_signal_connections()

        # 测试 4: 完整工作流
        test_workflow_integration()

        print("\n" + "="*60)
        print("✓ 所有测试通过！")
        print("="*60)
        return 0

    except AssertionError as e:
        print(f"\n✗ 测试失败: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ 意外错误: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
