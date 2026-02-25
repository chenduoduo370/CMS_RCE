# -*- coding: utf-8 -*-
"""
配置常量模块
提取所有魔法数字和配置项，便于统一管理和修改
"""

import os
from pathlib import Path


class Config:
    """全局配置类"""

    # ==================== 超时配置 ====================
    # 默认HTTP请求超时时间（秒）
    DEFAULT_REQUEST_TIMEOUT = 10

    # 指纹识别超时时间（秒）
    FINGERPRINT_TIMEOUT = 3.0

    # 端口扫描超时时间（秒）
    PORT_SCAN_TIMEOUT = 2.0

    # ==================== 端口扫描配置 ====================
    # 最大并发扫描线程数
    MAX_SCAN_WORKERS = 50

    # 常见端口扫描限制
    COMMON_PORTS_LIMIT = 100

    # ==================== 路径配置 ====================
    # 项目根目录
    PROJECT_ROOT = Path(__file__).parent.parent.absolute()

    # Payload模块目录
    PAYLOADS_DIR = "payloads"

    # 指纹-CVE映射文件
    FINGERPRINT_MAPPING_FILE = "fingerprint_cve_mapping.json"

    # ==================== HTTP配置 ====================
    # 默认User-Agent
    DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    # 是否验证SSL证书（默认不验证，用于渗透测试）
    VERIFY_SSL = False

    # ==================== 日志配置 ====================
    # 是否启用调试模式
    DEBUG = False

    # 日志格式
    LOG_FORMAT = "[%(levelname)s] %(message)s"

    # ==================== LLM配置 ====================
    # LLM API密钥（优先从环境变量读取）
    LLM_API_KEY = os.getenv('LLM_API_KEY', '')

    # LLM API基础URL（支持自定义端点）
    LLM_API_BASE = os.getenv('LLM_API_BASE', 'https://api.openai.com/v1')

    # LLM模型名称
    LLM_MODEL = os.getenv('LLM_MODEL', 'gpt-4')

    # LLM请求超时时间（秒）
    LLM_TIMEOUT = 30

    # LLM最大重试次数
    LLM_MAX_RETRIES = 3

    # 是否启用AI验证（可通过环境变量关闭）
    ENABLE_AI_VERIFICATION = os.getenv('ENABLE_AI_VERIFICATION', 'true').lower() == 'true'

    @classmethod
    def get_payloads_path(cls) -> Path:
        """获取Payload目录的绝对路径"""
        return cls.PROJECT_ROOT / cls.PAYLOADS_DIR

    @classmethod
    def get_mapping_file_path(cls) -> Path:
        """获取指纹映射文件的绝对路径"""
        return cls.PROJECT_ROOT / cls.FINGERPRINT_MAPPING_FILE

    @classmethod
    def is_llm_configured(cls) -> bool:
        """检查LLM是否已配置"""
        return bool(cls.LLM_API_KEY)
