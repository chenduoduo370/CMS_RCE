#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件MD5计算模块
通过URL下载文件并计算MD5哈希值
支持从HTML页面提取CSS文件并计算MD5
"""

import hashlib
import re
from html.parser import HTMLParser
from typing import Optional, List, Dict
from urllib.parse import urljoin

import requests


def calculate_file_md5_from_url(url: str, timeout: float = 3.0) -> Optional[str]:
    """
    通过URL下载文件并计算MD5值。
    
    Args:
        url: 文件的完整URL（如 http://192.168.1.1:80/core/CHANGELOG.txt）
        timeout: 请求超时时间（秒）
    
    Returns:
        文件的MD5哈希值（32位十六进制字符串），如果获取失败则返回None
    """
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        if response.status_code != 200:
            return None
        
        # 获取文件内容（二进制）
        content = response.content
        # 计算MD5
        md5_hash = hashlib.md5(content).hexdigest()
        return md5_hash
    except Exception:
        return None


def get_file_md5(url: str, timeout: float = 3.0) -> Optional[str]:
    """
    便捷函数：通过URL获取指定文件的MD5值。
    
    Args:
        url: 文件的完整URL（如 http://192.168.1.1:80/core/CHANGELOG.txt）
        timeout: 请求超时时间（秒）
    
    Returns:
        文件的MD5哈希值（32位十六进制字符串），如果获取失败则返回None
    """
    return calculate_file_md5_from_url(url, timeout)


class CSSLinkExtractor(HTMLParser):
    """HTML解析器，用于提取CSS文件链接"""
    
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.css_links: List[str] = []
    
    def handle_starttag(self, tag, attrs):
        if tag.lower() == 'link':
            attrs_dict = dict(attrs)
            rel = attrs_dict.get('rel', '').lower()
            href = attrs_dict.get('href', '')
            
            # 检查是否是stylesheet链接
            if rel == 'stylesheet' and href:
                # 将相对路径转换为绝对URL
                absolute_url = urljoin(self.base_url, href)
                self.css_links.append(absolute_url)
        
        # 也检查style标签中的@import
        elif tag.lower() == 'style':
            # style标签的内容会在handle_data中处理
            pass


def extract_css_links_from_html(html_content: str, base_url: str) -> List[str]:
    """
    从HTML内容中提取所有CSS文件链接。
    
    Args:
        html_content: HTML页面内容
        base_url: 基础URL，用于将相对路径转换为绝对URL
    
    Returns:
        CSS文件URL列表
    """
    parser = CSSLinkExtractor(base_url)
    parser.feed(html_content)
    
    # 也检查style标签中的@import规则
    import_pattern = r'@import\s+(?:url\()?["\']?([^"\']+)["\']?\)?'
    import_matches = re.findall(import_pattern, html_content, re.IGNORECASE)
    for match in import_matches:
        absolute_url = urljoin(base_url, match)
        if absolute_url not in parser.css_links:
            parser.css_links.append(absolute_url)
    
    return parser.css_links


def get_css_files_md5_from_page(page_url: str, timeout: float = 3.0) -> Dict[str, Optional[str]]:
    """
    访问指定页面，提取所有CSS文件链接，下载并计算每个CSS文件的MD5值。
    
    Args:
        page_url: 要访问的页面URL（如 http://192.168.1.1:80/）
        timeout: 请求超时时间（秒）
    
    Returns:
        字典，键为CSS文件URL，值为MD5哈希值（如果下载失败则为None）
    """
    result: Dict[str, Optional[str]] = {}
    
    try:
        # 访问页面
        response = requests.get(page_url, timeout=timeout, verify=False, allow_redirects=True)
        if response.status_code != 200:
            return result
        
        # 解析HTML，提取CSS链接
        html_content = response.text
        css_links = extract_css_links_from_html(html_content, page_url)
        
        if not css_links:
            return result
        
        # 下载每个CSS文件并计算MD5
        for css_url in css_links:
            md5_hash = calculate_file_md5_from_url(css_url, timeout)
            result[css_url] = md5_hash
        
        return result
    except Exception:
        return result


__all__ = [
    "calculate_file_md5_from_url",
    "get_file_md5",
    "extract_css_links_from_html",
    "get_css_files_md5_from_page",
]
