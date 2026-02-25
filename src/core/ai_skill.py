# -*- coding: utf-8 -*-
"""
AI技能模块
提供基于LLM的漏洞验证和Payload代码生成功能
"""

import ast
import json
import logging
import uuid
from typing import Dict, Optional, Tuple

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from ..config import Config
from ..exceptions import LLMAPIError, LLMConfigError, CodeGenerationError

# 配置日志
logger = logging.getLogger(__name__)


# ==================== AI验证引擎 ====================

# 系统提示词模板
VERIFICATION_SYSTEM_PROMPT = """你是一个网络安全专家，专门分析漏洞利用的HTTP响应。
你的任务是判断响应内容是否表明漏洞利用成功。

判断标准：
1. 真实漏洞回显：包含命令执行结果、系统信息、错误堆栈等
2. WAF拦截页面：包含"403 Forbidden"、"blocked"、"安全拦截"等
3. 语义假阳性：页面正常但恰好包含关键字（如文档中的"root"）

返回JSON格式：
{
  "is_vulnerable": true/false,
  "confidence": 0-100,
  "reason": "判断依据的详细说明"
}
"""

# 用户提示词模板
VERIFICATION_USER_PROMPT = """
CVE编号: {cve_id}
发送的Payload: {payload_sent}
HTTP响应内容:
{http_response_text}

请分析这个响应是否表明漏洞利用成功。
"""


def verify_response_with_ai(
    cve_id: str,
    payload_sent: str,
    http_response_text: str
) -> Optional[Dict[str, any]]:
    """
    使用AI语义分析验证漏洞利用响应

    Args:
        cve_id: CVE编号
        payload_sent: 发送的Payload内容
        http_response_text: HTTP响应文本

    Returns:
        验证结果字典，包含:
        - is_vulnerable: bool, 是否存在漏洞
        - confidence: int, 置信度(0-100)
        - reason: str, 判断依据
        如果AI验证失败则返回None（降级到传统验证）

    Raises:
        LLMConfigError: LLM配置错误
        LLMAPIError: LLM API调用失败
    """
    # 检查OpenAI库是否可用
    if not OPENAI_AVAILABLE:
        logger.warning("openai库未安装，跳过AI验证")
        return None

    # 检查配置
    if not Config.is_llm_configured():
        logger.warning("LLM未配置（缺少API密钥），跳过AI验证")
        return None

    if not Config.ENABLE_AI_VERIFICATION:
        logger.info("AI验证已禁用")
        return None

    try:
        # 初始化OpenAI客户端
        client = OpenAI(
            api_key=Config.LLM_API_KEY,
            base_url=Config.LLM_API_BASE,
            timeout=Config.LLM_TIMEOUT,
            max_retries=Config.LLM_MAX_RETRIES
        )

        # 构建用户提示词
        user_prompt = VERIFICATION_USER_PROMPT.format(
            cve_id=cve_id,
            payload_sent=payload_sent,
            http_response_text=http_response_text[:5000]  # 限制长度避免超出token限制
        )

        # 调用LLM API
        response = client.chat.completions.create(
            model=Config.LLM_MODEL,
            messages=[
                {"role": "system", "content": VERIFICATION_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1,  # 降低随机性，提高一致性
            response_format={"type": "json_object"}  # 要求返回JSON格式
        )

        # 解析响应
        result_text = response.choices[0].message.content
        result = json.loads(result_text)

        # 验证返回格式
        if not all(key in result for key in ['is_vulnerable', 'confidence', 'reason']):
            logger.error(f"LLM返回格式错误: {result}")
            return None

        # 记录结果
        logger.info(f"AI验证结果: 漏洞={result['is_vulnerable']}, "
                   f"置信度={result['confidence']}%, 原因={result['reason']}")

        return result

    except json.JSONDecodeError as e:
        logger.error(f"LLM返回的JSON解析失败: {e}")
        return None

    except Exception as e:
        logger.error(f"AI验证出现错误: {e}，回退到传统验证")
        return None


__all__ = [
    'verify_response_with_ai',
]
