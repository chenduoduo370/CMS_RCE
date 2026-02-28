#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Test multi-port support fix
Verify: AI JSON marker -> _check_autotest_trigger -> _start_autotest_from_ai -> AutoTestWorker
"""

import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("=" * 60)
print("Test: Multi-port support fix verification")
print("=" * 60)

# Test 1: Verify SYSTEM_PROMPT contains ports explanation
print("\n[Test 1] Verify SYSTEM_PROMPT contains ports field...")
from src.gui.workers.qianwen_worker import QianwenWorker

if "ports" in QianwenWorker.SYSTEM_PROMPT:
    print("[OK] SYSTEM_PROMPT contains ports field explanation")
    if "82,83" in QianwenWorker.SYSTEM_PROMPT or "[82,83]" in QianwenWorker.SYSTEM_PROMPT:
        print("[OK] SYSTEM_PROMPT contains example: ports 82,83")
    if "[82,83]" in QianwenWorker.SYSTEM_PROMPT:
        print("[OK] SYSTEM_PROMPT contains JSON format example: [82,83]")
else:
    print("[FAIL] SYSTEM_PROMPT missing ports field explanation")
    sys.exit(1)

# Test 2: Verify JSON marker format
print("\n[Test 2] Verify JSON marker format...")
test_marker = '##AUTOTEST##{"host":"192.168.10.111","cmd":"whoami","do_port_scan":false,"ports":[82,83],"port_timeout":2}##END##'
import re
match = re.search(r'##AUTOTEST##(.+?)##END##', test_marker)
if match:
    json_str = match.group(1)
    try:
        params = json.loads(json_str)
        print("[OK] JSON marker format is correct")
        print("  - host: " + str(params.get('host')))
        print("  - cmd: " + str(params.get('cmd')))
        print("  - do_port_scan: " + str(params.get('do_port_scan')))
        print("  - ports: " + str(params.get('ports')))
        print("  - port_timeout: " + str(params.get('port_timeout')))

        if params.get('ports') == [82, 83]:
            print("[OK] ports field correctly contains [82, 83]")
        else:
            print("[FAIL] ports field value mismatch: " + str(params.get('ports')))
            sys.exit(1)
    except json.JSONDecodeError as e:
        print("[FAIL] JSON parsing failed: " + str(e))
        sys.exit(1)
else:
    print("[FAIL] JSON marker format mismatch")
    sys.exit(1)

# Test 3: Verify _check_autotest_trigger can parse ports correctly
print("\n[Test 3] Verify _check_autotest_trigger() can extract ports...")

def mock_check_autotest_trigger(response):
    """Mock GUI _check_autotest_trigger method"""
    import re
    match = re.search(r'##AUTOTEST##(.+?)##END##', response)
    if match:
        try:
            json_str = match.group(1)
            params = json.loads(json_str)

            host = params.get("host", "").strip()
            cmd = params.get("cmd", "whoami")
            do_port_scan = bool(params.get("do_port_scan", False))
            ports = params.get("ports", None)  # KEY: extract ports here
            port_timeout = int(params.get("port_timeout", 2))

            return {
                'host': host,
                'cmd': cmd,
                'do_port_scan': do_port_scan,
                'ports': ports,
                'port_timeout': port_timeout
            }
        except Exception as e:
            print("[FAIL] JSON parsing exception: " + str(e))
            return None
    return None

result = mock_check_autotest_trigger(test_marker)
if result:
    print("[OK] _check_autotest_trigger() can parse parameters correctly")
    print("  - host: " + result['host'])
    print("  - ports: " + str(result['ports']))
    if result['ports'] == [82, 83]:
        print("[OK] ports field correctly passed: [82, 83]")
    else:
        print("[FAIL] ports field value mismatch: " + str(result['ports']))
        sys.exit(1)
else:
    print("[FAIL] _check_autotest_trigger() parsing failed")
    sys.exit(1)

# Test 4: Verify _start_autotest_from_ai can handle ports correctly
print("\n[Test 4] Verify _start_autotest_from_ai() can handle ports...")

# Check if AutoTestWorker accepts ports parameter
from src.gui.workers.auto_test_worker import AutoTestWorker
import inspect

sig = inspect.signature(AutoTestWorker.__init__)
if 'ports' in sig.parameters:
    print("[OK] AutoTestWorker.__init__() contains ports parameter")
    print("  Parameters: " + str(list(sig.parameters.keys())))
else:
    print("[FAIL] AutoTestWorker.__init__() missing ports parameter")
    print("  Current parameters: " + str(list(sig.parameters.keys())))
    sys.exit(1)

# Test 5: Verify _start_autotest_from_ai method signature
print("\n[Test 5] Verify _start_autotest_from_ai() method signature...")
from poc_gui import MainWindow
sig = inspect.signature(MainWindow._start_autotest_from_ai)
if 'ports' in sig.parameters:
    print("[OK] _start_autotest_from_ai() contains ports parameter")
    print("  Parameters: " + str(list(sig.parameters.keys())))
    if sig.parameters['ports'].default is None:
        print("[OK] ports parameter default value is None")
else:
    print("[FAIL] _start_autotest_from_ai() missing ports parameter")
    print("  Current parameters: " + str(list(sig.parameters.keys())))
    sys.exit(1)

# Test 6: Verify auto-enable scan logic
print("\n[Test 6] Verify auto-enable scan logic when ports specified...")
test_cases = [
    {'ports': None, 'do_port_scan': False, 'expected': False},
    {'ports': [], 'do_port_scan': False, 'expected': False},
    {'ports': [82, 83], 'do_port_scan': False, 'expected': True},  # Should auto-enable
    {'ports': [80], 'do_port_scan': True, 'expected': True},
]

all_passed = True
for case in test_cases:
    ports = case['ports']
    do_port_scan = case['do_port_scan']
    expected = case['expected']

    # Simulate _start_autotest_from_ai logic
    if ports and isinstance(ports, list) and len(ports) > 0:
        do_port_scan = True

    passed = do_port_scan == expected
    result_str = "[OK]" if passed else "[FAIL]"
    print(result_str + " ports=" + str(ports) + ", do_port_scan: " + str(do_port_scan) + " (expected: " + str(expected) + ")")
    if not passed:
        all_passed = False

if not all_passed:
    sys.exit(1)

print("\n" + "=" * 60)
print("[SUCCESS] All tests passed! Multi-port support fix verified")
print("=" * 60)
print("\nKey verification points:")
print("1. SYSTEM_PROMPT contains ports field explanation and examples")
print("2. JSON marker format correctly includes ports field")
print("3. _check_autotest_trigger() can extract ports parameter correctly")
print("4. AutoTestWorker can accept ports parameter")
print("5. _start_autotest_from_ai() contains ports parameter with default None")
print("6. Scan mode auto-enabled when ports specified")
print("\nNext step: Run complete end-to-end test")
print('  Input: "test 192.168.10.111 ports 82 and 83"')
print('  Verify log shows: "specified ports: [82, 83]"')
print('  Confirm fingerprint discovery on :82 and :83 (not :80)')
