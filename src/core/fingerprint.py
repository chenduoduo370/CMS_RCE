#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Web指纹识别模块
支持多种指纹识别方式：
1. 文件哈希指纹（MD5/SHA1/SHA256）
2. HTTP响应头指纹（Server, X-Powered-By等）
3. 静态资源指纹（CSS/JS/图片/字体等）
"""

import hashlib
import re
import sys
import os
from html.parser import HTMLParser
from typing import Optional, List, Dict, Tuple, Set
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# 添加src目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'src'))

try:
    from fingerprint_cve_mapping import get_manager
    from src.exceptions import FingerprintError, NetworkError
    from src.config import Config
    _cve_manager = None
    def _get_cve_manager():
        global _cve_manager
        if _cve_manager is None:
            _cve_manager = get_manager()
        return _cve_manager
except ImportError:
    # 后备方案
    class FingerprintError(Exception):
        """指纹识别错误异常"""
        pass

    class NetworkError(Exception):
        """网络请求失败异常"""
        pass

    class Config:
        """配置类（后备方案）"""
        DEFAULT_REQUEST_TIMEOUT = 10
        FINGERPRINT_TIMEOUT = 3.0
        DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        VERIFY_SSL = False

    _get_cve_manager = None


# 支持的哈希算法
HASH_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
}

# 常见的指纹识别HTTP头
FINGERPRINT_HEADERS = [
    'Server',
    'X-Powered-By',
    'X-Generator',
    'X-AspNet-Version',
    'X-AspNetMvc-Version',
    'X-Drupal-Cache',
    'X-Drupal-Dynamic-Cache',
    'X-Varnish',
    'X-Nginx-Cache-Status',
    'X-Cache',
    'X-Runtime',
    'X-Version',
]


def calculate_file_hash(content: bytes, algorithm: str = 'md5') -> str:
    """
    计算文件内容的哈希值

    Args:
        content: 文件内容（字节）
        algorithm: 哈希算法（md5/sha1/sha256）

    Returns:
        哈希值（十六进制字符串）

    Raises:
        FingerprintError: 不支持的哈希算法
    """
    if algorithm not in HASH_ALGORITHMS:
        raise FingerprintError(f"不支持的哈希算法: {algorithm}")

    hash_func = HASH_ALGORITHMS[algorithm]()
    hash_func.update(content)
    return hash_func.hexdigest()


def calculate_file_hash_from_url(url: str, timeout: float = None,
                                 algorithm: str = 'md5') -> Optional[str]:
    """
    通过URL下载文件并计算哈希值

    Args:
        url: 文件的完整URL
        timeout: 请求超时时间（秒），默认使用Config配置
        algorithm: 哈希算法（md5/sha1/sha256）

    Returns:
        文件的哈希值，如果获取失败则返回None

    Raises:
        NetworkError: 网络请求失败
        FingerprintError: 哈希计算失败
    """
    if timeout is None:
        timeout = Config.FINGERPRINT_TIMEOUT

    try:
        headers = {'User-Agent': Config.DEFAULT_USER_AGENT}
        response = requests.get(
            url,
            timeout=timeout,
            verify=Config.VERIFY_SSL,
            allow_redirects=True,
            headers=headers
        )

        if response.status_code != 200:
            return None

        return calculate_file_hash(response.content, algorithm)

    except requests.exceptions.Timeout:
        raise NetworkError(f"请求超时: {url}")
    except requests.exceptions.ConnectionError:
        raise NetworkError(f"连接失败: {url}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"请求失败: {url} - {e}")
    except Exception as e:
        raise FingerprintError(f"哈希计算失败: {e}")


def get_file_md5(url: str, timeout: float = None) -> Optional[str]:
    """
    便捷函数：通过URL获取指定文件的MD5值

    Args:
        url: 文件的完整URL
        timeout: 请求超时时间（秒）

    Returns:
        文件的MD5哈希值，如果获取失败则返回None
    """
    try:
        return calculate_file_hash_from_url(url, timeout, 'md5')
    except (NetworkError, FingerprintError):
        return None


def get_file_md5_with_cve(url: str, timeout: float = None) -> Tuple[Optional[str], Optional[str]]:
    """
    通过URL获取指定文件的MD5值，并查找对应的CVE

    Args:
        url: 文件的完整URL
        timeout: 请求超时时间（秒）

    Returns:
        元组(MD5哈希值, CVE编号)
    """
    try:
        md5_hash = calculate_file_hash_from_url(url, timeout, 'md5')
        cve_id = None

        if md5_hash and _get_cve_manager:
            cve_manager = _get_cve_manager()
            if cve_manager:
                cve_id = cve_manager.get_cve(md5_hash)

        return (md5_hash, cve_id)
    except (NetworkError, FingerprintError):
        return (None, None)


def extract_http_headers_fingerprint(url: str, timeout: float = None) -> Dict[str, str]:
    """
    提取HTTP响应头中的指纹信息

    Args:
        url: 目标URL
        timeout: 请求超时时间（秒）

    Returns:
        包含指纹信息的字典

    Raises:
        NetworkError: 网络请求失败
    """
    if timeout is None:
        timeout = Config.FINGERPRINT_TIMEOUT

    fingerprints = {}

    try:
        headers = {'User-Agent': Config.DEFAULT_USER_AGENT}
        response = requests.get(
            url,
            timeout=timeout,
            verify=Config.VERIFY_SSL,
            allow_redirects=True,
            headers=headers
        )

        # 提取指纹相关的HTTP头
        for header in FINGERPRINT_HEADERS:
            value = response.headers.get(header)
            if value:
                fingerprints[header] = value

        return fingerprints

    except requests.exceptions.Timeout:
        raise NetworkError(f"请求超时: {url}")
    except requests.exceptions.ConnectionError:
        raise NetworkError(f"连接失败: {url}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"请求失败: {url} - {e}")


class ResourceExtractor(HTMLParser):
    """HTML解析器，用于提取各种静态资源链接"""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.css_links: Set[str] = set()
        self.js_links: Set[str] = set()
        self.img_links: Set[str] = set()
        self.font_links: Set[str] = set()

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        # CSS文件
        if tag.lower() == 'link':
            rel = attrs_dict.get('rel', '').lower()
            href = attrs_dict.get('href', '')

            if rel == 'stylesheet' and href:
                absolute_url = urljoin(self.base_url, href)
                self.css_links.add(absolute_url)

        # JavaScript文件
        elif tag.lower() == 'script':
            src = attrs_dict.get('src', '')
            if src:
                absolute_url = urljoin(self.base_url, src)
                self.js_links.add(absolute_url)

        # 图片文件
        elif tag.lower() == 'img':
            src = attrs_dict.get('src', '')
            if src:
                absolute_url = urljoin(self.base_url, src)
                self.img_links.add(absolute_url)


def extract_resources_from_css(css_content: str, base_url: str) -> Dict[str, List[str]]:
    """
    从CSS内容中提取资源链接（字体、图片等）

    Args:
        css_content: CSS文件内容
        base_url: CSS文件的URL（用于解析相对路径）

    Returns:
        资源字典，包含 img, font 等类型
    """
    img_links: Set[str] = set()
    font_links: Set[str] = set()

    # 提取所有url()引用
    url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
    url_matches = re.findall(url_pattern, css_content, re.IGNORECASE)

    for url in url_matches:
        url = url.strip()
        # 跳过data URI
        if url.startswith('data:'):
            continue

        absolute_url = urljoin(base_url, url)

        # 根据扩展名分类
        lower_url = url.lower()
        if any(ext in lower_url for ext in ['.woff', '.woff2', '.ttf', '.eot', '.otf']):
            font_links.add(absolute_url)
        elif any(ext in lower_url for ext in ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.webp', '.bmp', '.ico']):
            img_links.add(absolute_url)

    return {
        'img': list(img_links),
        'font': list(font_links),
    }


def extract_resources_from_html(html_content: str, base_url: str) -> Dict[str, List[str]]:
    """
    从HTML内容中提取所有静态资源链接

    Args:
        html_content: HTML页面内容
        base_url: 基础URL

    Returns:
        资源字典，包含 css, js, img, font 等类型
    """
    parser = ResourceExtractor(base_url)
    parser.feed(html_content)

    # 也检查style标签中的@import规则
    import_pattern = r'@import\s+(?:url\()?["\']?([^"\']+)["\']?\)?'
    import_matches = re.findall(import_pattern, html_content, re.IGNORECASE)
    for match in import_matches:
        absolute_url = urljoin(base_url, match)
        parser.css_links.add(absolute_url)

    # 检查内联样式中的资源
    inline_resources = extract_resources_from_css(html_content, base_url)
    parser.img_links.update(inline_resources.get('img', []))
    parser.font_links.update(inline_resources.get('font', []))

    return {
        'css': list(parser.css_links),
        'js': list(parser.js_links),
        'img': list(parser.img_links),
        'font': list(parser.font_links),
    }


def extract_css_links_from_html(html_content: str, base_url: str) -> List[str]:
    """
    从HTML内容中提取所有CSS文件链接（向后兼容）

    Args:
        html_content: HTML页面内容
        base_url: 基础URL

    Returns:
        CSS文件URL列表
    """
    resources = extract_resources_from_html(html_content, base_url)
    return resources['css']


def get_css_files_md5_from_page(page_url: str, timeout: float = None) -> Dict[str, Tuple[Optional[str], Optional[str]]]:
    """
    访问指定页面，提取所有CSS文件链接，下载并计算每个CSS文件的MD5值，并查找对应的CVE
    （向后兼容函数）

    Args:
        page_url: 要访问的页面URL
        timeout: 请求超时时间（秒）

    Returns:
        字典，键为CSS文件URL，值为元组(MD5哈希值, CVE编号)
    """
    result = get_resources_fingerprint_from_page(
        page_url,
        timeout=timeout,
        resource_types=['css'],
        algorithms=['md5']
    )

    # 转换格式以保持向后兼容
    css_result = {}
    for url, hashes in result.items():
        md5_hash = hashes.get('md5')
        cve_id = hashes.get('cve')
        css_result[url] = (md5_hash, cve_id)

    return css_result


def get_resources_fingerprint_from_page(
    page_url: str,
    timeout: float = None,
    resource_types: List[str] = None,
    algorithms: List[str] = None,
    max_workers: int = 5
) -> Dict[str, Dict[str, Optional[str]]]:
    """
    访问指定页面，提取静态资源并计算指纹

    Args:
        page_url: 要访问的页面URL
        timeout: 请求超时时间（秒）
        resource_types: 要提取的资源类型列表，默认 ['css', 'js']
        algorithms: 要使用的哈希算法列表，默认 ['md5']
        max_workers: 最大并发下载数

    Returns:
        字典，键为资源URL，值为包含各种哈希值和CVE的字典
        例如: {
            'http://example.com/style.css': {
                'md5': 'abc123...',
                'sha1': 'def456...',
                'cve': 'CVE-2019-1234'
            }
        }

    Raises:
        NetworkError: 网络请求失败
    """
    if timeout is None:
        timeout = Config.FINGERPRINT_TIMEOUT

    if resource_types is None:
        resource_types = ['css', 'js']

    if algorithms is None:
        algorithms = ['md5']

    result: Dict[str, Dict[str, Optional[str]]] = {}

    try:
        # 访问页面
        headers = {'User-Agent': Config.DEFAULT_USER_AGENT}
        response = requests.get(
            page_url,
            timeout=timeout,
            verify=Config.VERIFY_SSL,
            allow_redirects=True,
            headers=headers
        )

        if response.status_code != 200:
            return result

        # 解析HTML，提取资源链接
        html_content = response.text
        resources = extract_resources_from_html(html_content, page_url)

        # 如果需要提取img或font，先下载CSS文件并解析
        if ('img' in resource_types or 'font' in resource_types) and 'css' in resources:
            for css_url in resources['css']:
                try:
                    css_resp = requests.get(
                        css_url,
                        timeout=timeout,
                        verify=Config.VERIFY_SSL,
                        headers=headers
                    )
                    if css_resp.status_code == 200:
                        css_content = css_resp.text
                        css_resources = extract_resources_from_css(css_content, css_url)

                        # 合并CSS中提取的资源
                        if 'img' in resource_types and 'img' in css_resources:
                            resources.setdefault('img', []).extend(css_resources['img'])
                        if 'font' in resource_types and 'font' in css_resources:
                            resources.setdefault('font', []).extend(css_resources['font'])
                except Exception:
                    # 忽略单个CSS文件的解析错误
                    pass

        # 收集需要下载的资源URL（去重）
        urls_to_download = []
        seen_urls = set()
        for res_type in resource_types:
            if res_type in resources:
                for url in resources[res_type]:
                    if url not in seen_urls:
                        urls_to_download.append(url)
                        seen_urls.add(url)

        if not urls_to_download:
            return result

        # 获取CVE管理器（如果可用）
        cve_manager = _get_cve_manager() if _get_cve_manager else None

        # 并发下载资源并计算哈希
        def download_and_hash(url: str) -> Tuple[str, Dict[str, Optional[str]]]:
            hashes = {}
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    verify=Config.VERIFY_SSL,
                    headers=headers
                )

                if resp.status_code == 200:
                    content = resp.content

                    # 计算所有请求的哈希算法
                    for algo in algorithms:
                        try:
                            hashes[algo] = calculate_file_hash(content, algo)
                        except FingerprintError:
                            hashes[algo] = None

                    # 如果计算了MD5，尝试查找对应的CVE
                    if 'md5' in hashes and hashes['md5'] and cve_manager:
                        hashes['cve'] = cve_manager.get_cve(hashes['md5'])
                    else:
                        hashes['cve'] = None

            except Exception:
                # 下载失败，返回空哈希
                for algo in algorithms:
                    hashes[algo] = None
                hashes['cve'] = None

            return (url, hashes)

        # 使用线程池并发下载
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(download_and_hash, url) for url in urls_to_download]

            for future in as_completed(futures):
                try:
                    url, hashes = future.result()
                    result[url] = hashes
                except Exception:
                    # 忽略单个资源的错误
                    pass

        return result

    except requests.exceptions.Timeout:
        raise NetworkError(f"请求超时: {page_url}")
    except requests.exceptions.ConnectionError:
        raise NetworkError(f"连接失败: {page_url}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"请求失败: {page_url} - {e}")


def extract_page_features(html_content: str, url: str) -> Dict[str, any]:
    """
    Extract page features for fingerprinting (forms, titles, specific HTML patterns)
    Used when no CSS/JS resources are available.

    Args:
        html_content: HTML page content
        url: Base URL for reference

    Returns:
        Dictionary containing page features:
        {
            'title': str,
            'forms': [{'action': str, 'method': str, 'fields': [str], 'enctype': str}],
            'headings': [str],
            'meta_tags': [{'name': str, 'content': str}],
            'scripts_inline': int,
            'comments': [str],
            'signature_hash': str,  # MD5 of combined features
        }
    """
    features = {
        'title': '',
        'forms': [],
        'headings': [],
        'meta_tags': [],
        'scripts_inline': 0,
        'comments': [],
        'signature_hash': None,
    }

    # Extract title
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
    if title_match:
        features['title'] = title_match.group(1).strip()

    # Extract forms with details
    form_pattern = r'<form[^>]*>(.*?)</form>'
    for form_match in re.finditer(form_pattern, html_content, re.IGNORECASE | re.DOTALL):
        form_html = form_match.group(0)
        form_info = {
            'action': '',
            'method': 'GET',
            'enctype': '',
            'fields': [],
        }

        # Extract form attributes
        action_match = re.search(r'action=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE)
        if action_match:
            form_info['action'] = action_match.group(1)

        method_match = re.search(r'method=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE)
        if method_match:
            form_info['method'] = method_match.group(1).upper()

        enctype_match = re.search(r'enctype=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE)
        if enctype_match:
            form_info['enctype'] = enctype_match.group(1)

        # Extract input field names
        for input_match in re.finditer(r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE):
            form_info['fields'].append(input_match.group(1))

        # Extract textarea names
        for textarea_match in re.finditer(r'<textarea[^>]*name=["\']?([^"\'>\s]+)["\']?', form_html, re.IGNORECASE):
            form_info['fields'].append(textarea_match.group(1))

        features['forms'].append(form_info)

    # Extract headings
    for h_match in re.finditer(r'<h[1-6][^>]*>(.*?)</h[1-6]>', html_content, re.IGNORECASE | re.DOTALL):
        heading_text = re.sub(r'<[^>]+>', '', h_match.group(1)).strip()
        if heading_text:
            features['headings'].append(heading_text)

    # Extract meta tags
    for meta_match in re.finditer(r'<meta[^>]*>', html_content, re.IGNORECASE):
        meta_html = meta_match.group(0)
        meta_info = {}
        name_match = re.search(r'name=["\']?([^"\'>\s]+)["\']?', meta_html, re.IGNORECASE)
        content_match = re.search(r'content=["\']?([^"\']*)["\']?', meta_html, re.IGNORECASE)
        if name_match and content_match:
            meta_info['name'] = name_match.group(1)
            meta_info['content'] = content_match.group(1)
            features['meta_tags'].append(meta_info)

    # Count inline scripts
    features['scripts_inline'] = len(re.findall(r'<script[^>]*>(?!</script>).*?</script>', html_content, re.IGNORECASE | re.DOTALL))

    # Extract HTML comments
    for comment_match in re.finditer(r'<!--(.*?)-->', html_content, re.DOTALL):
        comment = comment_match.group(1).strip()
        if comment:
            features['comments'].append(comment)

    # Generate signature hash from combined features
    signature_parts = []
    if features['title']:
        signature_parts.append(f"title:{features['title']}")
    for form in features['forms']:
        signature_parts.append(f"form:{form['method']}:{form['action']}:{','.join(sorted(form['fields']))}")
    for heading in features['headings']:
        signature_parts.append(f"h:{heading}")

    if signature_parts:
        signature_str = '|'.join(signature_parts)
        features['signature_hash'] = hashlib.md5(signature_str.encode('utf-8')).hexdigest()

    return features


def match_page_features_to_cve(features: Dict[str, any], cve_manager=None) -> List[Dict[str, str]]:
    """
    Match page features to known CVE patterns.

    Args:
        features: Page features from extract_page_features
        cve_manager: CVE mapping manager (optional)

    Returns:
        List of matched CVEs with confidence:
        [{'cve_id': str, 'confidence': str, 'reason': str}]
    """
    matches = []

    # PHPMailer vulnerable form pattern (CVE-2016-10033)
    # Characteristics: form with enctype="multipart/form-data", email field, vulnerable mail form title
    for form in features.get('forms', []):
        form_fields = set(form.get('fields', []))

        # PHPMailer pattern: name, email, message fields with multipart form
        if form_fields >= {'name', 'email', 'message'}:
            if 'multipart/form-data' in form.get('enctype', '').lower():
                matches.append({
                    'cve_id': 'CVE-2016-10033',
                    'confidence': 'high',
                    'reason': 'PHPMailer vulnerable form detected (multipart form with name/email/message fields)'
                })

        # Alternative PHPMailer pattern: just email field with submit
        elif 'email' in form_fields and features.get('title', '').lower().find('mail') >= 0:
            matches.append({
                'cve_id': 'CVE-2016-10033',
                'confidence': 'medium',
                'reason': 'Mail form with email field detected'
            })

    # Drupal patterns (CVE-2018-7600, CVE-2019-6340)
    title_lower = features.get('title', '').lower()
    headings_lower = ' '.join(features.get('headings', [])).lower()

    if 'drupal' in title_lower or 'drupal' in headings_lower:
        matches.append({
            'cve_id': 'CVE-2018-7600',
            'confidence': 'medium',
            'reason': 'Drupal detected in page title/headings'
        })
        matches.append({
            'cve_id': 'CVE-2019-6340',
            'confidence': 'medium',
            'reason': 'Drupal detected in page title/headings'
        })

    # Check signature hash in CVE mapping if available
    if cve_manager and features.get('signature_hash'):
        cve_id = cve_manager.get_cve(features['signature_hash'])
        if cve_id:
            matches.append({
                'cve_id': cve_id,
                'confidence': 'high',
                'reason': f'Signature hash matched: {features["signature_hash"]}'
            })

    return matches


def get_page_feature_fingerprint(url: str, timeout: float = None) -> Dict[str, any]:
    """
    Get page feature fingerprint for targets without CSS/JS resources.

    Args:
        url: Target URL
        timeout: Request timeout in seconds

    Returns:
        Dictionary with page features and matched CVEs:
        {
            'features': {...},
            'matched_cves': [...],
        }
    """
    if timeout is None:
        timeout = Config.FINGERPRINT_TIMEOUT

    result = {
        'features': {},
        'matched_cves': [],
    }

    try:
        headers = {'User-Agent': Config.DEFAULT_USER_AGENT}
        response = requests.get(
            url,
            timeout=timeout,
            verify=Config.VERIFY_SSL,
            allow_redirects=True,
            headers=headers
        )

        if response.status_code != 200:
            return result

        html_content = response.text

        # Extract page features
        features = extract_page_features(html_content, url)
        result['features'] = features

        # Get CVE manager if available
        cve_manager = _get_cve_manager() if _get_cve_manager else None

        # Match features to CVEs
        matched = match_page_features_to_cve(features, cve_manager)
        result['matched_cves'] = matched

        return result

    except requests.exceptions.Timeout:
        raise NetworkError(f"Request timeout: {url}")
    except requests.exceptions.ConnectionError:
        raise NetworkError(f"Connection failed: {url}")
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Request failed: {url} - {e}")


def get_comprehensive_fingerprint(url: str, timeout: float = None) -> Dict[str, any]:
    """
    获取目标的综合指纹信息

    Args:
        url: 目标URL
        timeout: 请求超时时间（秒）

    Returns:
        包含所有指纹信息的字典:
        {
            'http_headers': {...},  # HTTP头指纹
            'resources': {...},     # 静态资源指纹
        }
    """
    if timeout is None:
        timeout = Config.FINGERPRINT_TIMEOUT

    fingerprint = {
        'http_headers': {},
        'resources': {},
    }

    try:
        # 提取HTTP头指纹
        fingerprint['http_headers'] = extract_http_headers_fingerprint(url, timeout)
    except NetworkError:
        pass

    try:
        # 提取资源指纹
        fingerprint['resources'] = get_resources_fingerprint_from_page(
            url,
            timeout=timeout,
            resource_types=['css', 'js'],
            algorithms=['md5', 'sha1']
        )
    except NetworkError:
        pass

    return fingerprint


__all__ = [
    "calculate_file_hash",
    "calculate_file_hash_from_url",
    "get_file_md5",
    "get_file_md5_with_cve",
    "extract_http_headers_fingerprint",
    "extract_resources_from_html",
    "extract_css_links_from_html",
    "get_css_files_md5_from_page",
    "get_resources_fingerprint_from_page",
    "get_comprehensive_fingerprint",
    "extract_page_features",
    "match_page_features_to_cve",
    "get_page_feature_fingerprint",
    "FingerprintError",
    "NetworkError",
]
