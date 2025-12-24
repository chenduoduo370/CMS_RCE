#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口识别模块
用于检测目标主机是否开放了指定端口
"""

import socket
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed


# 常见服务端口
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def check_port(host: str, port: int, timeout: float = 2.0) -> Tuple[int, bool, Optional[str]]:
    """
    检测单个端口是否开放
    
    Args:
        host: 目标主机IP或域名
        port: 端口号
        timeout: 超时时间（秒）
    
    Returns:
        元组(端口号, 是否开放, 服务名称)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            service_name = COMMON_PORTS.get(port, "Unknown")
            return (port, True, service_name)
        else:
            return (port, False, None)
    except socket.gaierror:
        # 域名解析失败
        return (port, False, None)
    except socket.timeout:
        return (port, False, None)
    except Exception:
        return (port, False, None)


def scan_ports(host: str, ports: List[int] = None, timeout: float = 2.0, 
               max_workers: int = 50) -> Dict[int, Tuple[bool, Optional[str]]]:
    """
    扫描多个端口
    
    Args:
        host: 目标主机IP或域名
        ports: 要扫描的端口列表，默认为常见端口
        timeout: 每个端口的超时时间（秒）
        max_workers: 最大并发线程数
    
    Returns:
        字典，键为端口号，值为元组(是否开放, 服务名称)
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    
    results: Dict[int, Tuple[bool, Optional[str]]] = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_port, host, port, timeout): port for port in ports}
        
        for future in as_completed(futures):
            port, is_open, service = future.result()
            results[port] = (is_open, service)
    
    return results


def scan_common_ports(host: str, timeout: float = 2.0) -> Dict[int, str]:
    """
    扫描常见端口，只返回开放的端口
    
    Args:
        host: 目标主机IP或域名
        timeout: 每个端口的超时时间（秒）
    
    Returns:
        字典，键为开放的端口号，值为服务名称
    """
    results = scan_ports(host, timeout=timeout)
    return {port: service for port, (is_open, service) in results.items() if is_open}


def scan_port_range(host: str, start_port: int, end_port: int, 
                    timeout: float = 1.0, max_workers: int = 100) -> List[int]:
    """
    扫描端口范围
    
    Args:
        host: 目标主机IP或域名
        start_port: 起始端口
        end_port: 结束端口
        timeout: 每个端口的超时时间（秒）
        max_workers: 最大并发线程数
    
    Returns:
        开放的端口列表
    """
    ports = list(range(start_port, end_port + 1))
    results = scan_ports(host, ports, timeout, max_workers)
    return sorted([port for port, (is_open, _) in results.items() if is_open])


def format_scan_result(results: Dict[int, Tuple[bool, Optional[str]]]) -> str:
    """
    格式化扫描结果为字符串
    
    Args:
        results: scan_ports 返回的结果
    
    Returns:
        格式化的字符串
    """
    lines = []
    open_ports = [(port, service) for port, (is_open, service) in sorted(results.items()) if is_open]
    closed_count = len(results) - len(open_ports)
    
    if open_ports:
        lines.append(f"开放的端口 ({len(open_ports)} 个):")
        for port, service in open_ports:
            lines.append(f"  {port}/tcp  open  {service or 'Unknown'}")
    else:
        lines.append("未发现开放的端口")
    
    lines.append(f"\n已扫描 {len(results)} 个端口，{closed_count} 个关闭")
    
    return "\n".join(lines)


__all__ = [
    "check_port",
    "scan_ports", 
    "scan_common_ports",
    "scan_port_range",
    "format_scan_result",
    "COMMON_PORTS",
]

