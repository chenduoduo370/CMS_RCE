# -*- coding: utf-8 -*-
"""
URL工具模块
统一处理URL解析和规范化，消除代码重复
"""

from urllib.parse import urlparse, urljoin
from typing import Tuple, Optional


def normalize_url(url: str, ip_port: Optional[str] = None) -> str:
    """
    标准化URL
    - 如果是完整URL（包含http://或https://），直接返回
    - 如果是路径，补全协议和主机

    Args:
        url: URL或路径
        ip_port: 目标IP和端口，格式为 "192.168.1.1:80"

    Returns:
        str: 标准化后的完整URL

    Raises:
        ValueError: 如果url是路径但未提供ip_port参数

    Examples:
        >>> normalize_url("http://example.com/path")
        'http://example.com/path'
        >>> normalize_url("/api/test", "192.168.1.1:80")
        'http://192.168.1.1:80/api/test'
        >>> normalize_url("api/test", "192.168.1.1:80")
        'http://192.168.1.1:80/api/test'
    """
    # 如果已经是完整URL，直接返回
    if url.startswith(('http://', 'https://')):
        return url

    # 如果是路径，需要ip_port参数
    if not ip_port:
        raise ValueError("需要提供ip_port参数来构建完整URL")

    # 确保路径以/开头
    path = url if url.startswith('/') else f'/{url}'

    # 构建完整URL
    return f'http://{ip_port}{path}'


def extract_path_from_url(url: str) -> str:
    """
    从完整URL中提取路径（包括查询参数和片段）

    Args:
        url: 完整的URL

    Returns:
        str: URL路径部分（包括查询参数和片段）

    Examples:
        >>> extract_path_from_url("http://example.com/api/test")
        '/api/test'
        >>> extract_path_from_url("http://example.com/api/test?id=1#section")
        '/api/test?id=1#section'
        >>> extract_path_from_url("http://example.com")
        '/'
    """
    parsed = urlparse(url)

    # 获取路径，如果为空则使用'/'
    path = parsed.path or '/'

    # 添加查询参数
    if parsed.query:
        path += f'?{parsed.query}'

    # 添加片段
    if parsed.fragment:
        path += f'#{parsed.fragment}'

    return path


def extract_host_port(url: str) -> Tuple[str, int]:
    """
    从URL中提取主机和端口

    Args:
        url: 完整的URL

    Returns:
        Tuple[str, int]: (主机名, 端口号)

    Examples:
        >>> extract_host_port("http://example.com:8080/path")
        ('example.com', 8080)
        >>> extract_host_port("https://example.com/path")
        ('example.com', 443)
        >>> extract_host_port("http://192.168.1.1/path")
        ('192.168.1.1', 80)
    """
    parsed = urlparse(url)

    # 获取主机名
    host = parsed.hostname or ''

    # 获取端口，如果未指定则根据协议使用默认端口
    if parsed.port:
        port = parsed.port
    else:
        port = 443 if parsed.scheme == 'https' else 80

    return host, port


def extract_ip_port(url: str) -> str:
    """
    从URL中提取IP:端口格式的字符串

    Args:
        url: 完整的URL

    Returns:
        str: "IP:端口" 格式的字符串

    Examples:
        >>> extract_ip_port("http://192.168.1.1:8080/path")
        '192.168.1.1:8080'
        >>> extract_ip_port("http://example.com/path")
        'example.com:80'
    """
    host, port = extract_host_port(url)
    return f'{host}:{port}'


def is_valid_url(url: str) -> bool:
    """
    检查URL是否有效

    Args:
        url: 要检查的URL

    Returns:
        bool: URL是否有效

    Examples:
        >>> is_valid_url("http://example.com")
        True
        >>> is_valid_url("not a url")
        False
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False
