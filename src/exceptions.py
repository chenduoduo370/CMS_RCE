# -*- coding: utf-8 -*-
"""
自定义异常类模块
定义项目中使用的所有自定义异常
"""


class CVEToolException(Exception):
    """CVE工具基础异常类"""
    pass


class PayloadLoadError(CVEToolException):
    """Payload模块加载失败异常"""
    pass


class PayloadBuildError(CVEToolException):
    """Payload构建失败异常"""
    pass


class NetworkError(CVEToolException):
    """网络请求失败异常"""
    pass


class ParseError(CVEToolException):
    """数据解析错误异常"""
    pass


class FingerprintError(CVEToolException):
    """指纹识别错误异常"""
    pass


class PortScanError(CVEToolException):
    """端口扫描错误异常"""
    pass


class MappingError(CVEToolException):
    """指纹-CVE映射错误异常"""
    pass


class AIError(CVEToolException):
    """AI功能相关错误的基类"""
    pass


class LLMAPIError(AIError):
    """LLM API调用失败"""
    pass


class LLMConfigError(AIError):
    """LLM配置错误"""
    pass
