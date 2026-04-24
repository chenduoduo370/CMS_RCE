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

    @classmethod
    def get_payloads_path(cls) -> Path:
        """获取Payload目录的绝对路径"""
        return cls.PROJECT_ROOT / cls.PAYLOADS_DIR

    @classmethod
    def get_mapping_file_path(cls) -> Path:
        """获取指纹映射文件的绝对路径"""
        return cls.PROJECT_ROOT / cls.FINGERPRINT_MAPPING_FILE

    # ==================== AI API Configuration ====================
    # Qianwen (Alibaba Cloud) OpenAI-compatible API Base URL
    QIANWEN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"

    # ZhipuAI (GLM) OpenAI-compatible API Base URL
    ZHIPU_BASE_URL = "https://open.bigmodel.cn/api/paas/v4/"

    # Supported models list (for GUI dropdown)
    # Format: "provider:model" for backend routing
    AI_MODELS = [
        "qwen-plus",
        "qwen-turbo",
        "qwen-max",
        "glm-4",
        "glm-4-flash",
        "glm-4-plus",
        "glm-5",
    ]

    # Legacy alias for backward compatibility
    QIANWEN_MODELS = ["qwen-plus", "qwen-turbo", "qwen-max", "glm-4", "glm-4-flash", "glm-4-plus", "glm-5"]

    # Default model
    QIANWEN_DEFAULT_MODEL = "qwen-plus"

    # Model to base_url mapping
    MODEL_BASE_URL_MAP = {
        "qwen-plus": QIANWEN_BASE_URL,
        "qwen-turbo": QIANWEN_BASE_URL,
        "qwen-max": QIANWEN_BASE_URL,
        "glm-4": ZHIPU_BASE_URL,
        "glm-4-flash": ZHIPU_BASE_URL,
        "glm-4-plus": ZHIPU_BASE_URL,
        "glm-5": ZHIPU_BASE_URL,
    }

    # 配置文件路径（相对项目根目录，保存用户的 API Key）
    AI_CONFIG_FILE = "ai_config.json"

    @classmethod
    def get_ai_config_path(cls) -> Path:
        """获取 AI 配置文件的绝对路径"""
        return cls.PROJECT_ROOT / cls.AI_CONFIG_FILE

    @classmethod
    def is_llm_configured(cls) -> bool:
        """检查千问 API 是否已配置"""
        config_path = cls.get_ai_config_path()
        if config_path.exists():
            try:
                import json
                with open(config_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return bool(data.get("api_key", "").strip())
            except Exception:
                pass
        return False
