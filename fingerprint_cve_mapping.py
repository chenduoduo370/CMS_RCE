#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
指纹与CVE映射管理模块
支持自定义指纹（MD5值等）与CVE编号的一一对应关系
"""

import os
import sys
import json
import re
from typing import Dict, Optional, List
from dataclasses import dataclass

# 添加src目录到路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(current_dir, 'src'))

try:
    from src.exceptions import MappingError
    from src.config import Config
except ImportError:
    # 如果导入失败，定义本地版本
    class MappingError(Exception):
        """指纹-CVE映射错误异常"""
        pass

    class Config:
        """配置类（后备方案）"""
        @staticmethod
        def get_mapping_file_path():
            return os.path.join(current_dir, "fingerprint_cve_mapping.json")


# CVE ID 格式验证正则表达式
CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)

# MD5 格式验证正则表达式（32位十六进制）
MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')


@dataclass
class FingerprintCVEMapping:
    """指纹-CVE映射项"""
    fingerprint: str  # 指纹（如MD5值）
    cve_id: Optional[str]  # CVE编号，可以为空
    description: Optional[str] = None  # 描述信息（可选）


class FingerprintCVEManager:
    """指纹-CVE映射管理器"""

    def __init__(self, config_file: str = None):
        """
        初始化管理器

        Args:
            config_file: 配置文件路径，默认使用Config中的配置
        """
        if config_file is None:
            try:
                config_file = str(Config.get_mapping_file_path())
            except Exception:
                config_file = os.path.join(current_dir, "fingerprint_cve_mapping.json")

        self.config_file = config_file
        self.mappings: Dict[str, FingerprintCVEMapping] = {}
        self.load()

    def load(self) -> None:
        """从文件加载映射关系"""
        if not os.path.exists(self.config_file):
            self.mappings = {}
            return

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.mappings = {
                    fp: FingerprintCVEMapping(**item)
                    for fp, item in data.items()
                }
        except json.JSONDecodeError as e:
            raise MappingError(f"映射文件JSON格式错误: {e}")
        except (IOError, OSError) as e:
            raise MappingError(f"无法读取映射文件: {e}")
        except Exception as e:
            raise MappingError(f"加载映射文件失败: {e}")

    def save(self) -> bool:
        """保存映射关系到文件"""
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.config_file) or '.', exist_ok=True)

            # 转换为可序列化的格式
            data = {
                fp: {
                    "fingerprint": mapping.fingerprint,
                    "cve_id": mapping.cve_id,
                    "description": mapping.description,
                }
                for fp, mapping in self.mappings.items()
            }

            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return True
        except (IOError, OSError) as e:
            raise MappingError(f"无法写入映射文件: {e}")
        except Exception as e:
            raise MappingError(f"保存映射文件失败: {e}")

    @staticmethod
    def validate_cve_id(cve_id: Optional[str]) -> bool:
        """
        验证CVE ID格式

        Args:
            cve_id: CVE编号

        Returns:
            是否有效
        """
        if cve_id is None:
            return True
        return bool(CVE_ID_PATTERN.match(cve_id))

    @staticmethod
    def validate_md5(fingerprint: str) -> bool:
        """
        验证MD5格式

        Args:
            fingerprint: 指纹字符串

        Returns:
            是否为有效的MD5
        """
        return bool(MD5_PATTERN.match(fingerprint))

    def add_mapping(self, fingerprint: str, cve_id: Optional[str] = None,
                   description: Optional[str] = None, validate: bool = True) -> bool:
        """
        添加或更新指纹-CVE映射

        Args:
            fingerprint: 指纹（如MD5值）
            cve_id: CVE编号，可以为None
            description: 描述信息（可选）
            validate: 是否验证输入格式

        Returns:
            是否成功

        Raises:
            MappingError: 输入验证失败时
        """
        if not fingerprint:
            raise MappingError("指纹不能为空")

        if validate:
            if cve_id and not self.validate_cve_id(cve_id):
                raise MappingError(f"无效的CVE ID格式: {cve_id}（应为 CVE-YYYY-NNNNN）")

        self.mappings[fingerprint] = FingerprintCVEMapping(
            fingerprint=fingerprint,
            cve_id=cve_id,
            description=description
        )
        return self.save()

    def bulk_add_mappings(self, mappings: List[Dict[str, Optional[str]]],
                         validate: bool = True) -> int:
        """
        批量添加映射关系

        Args:
            mappings: 映射列表，每项包含 fingerprint, cve_id, description
            validate: 是否验证输入格式

        Returns:
            成功添加的数量

        Raises:
            MappingError: 验证失败或保存失败时
        """
        added_count = 0

        for item in mappings:
            fingerprint = item.get('fingerprint')
            cve_id = item.get('cve_id')
            description = item.get('description')

            if not fingerprint:
                continue

            if validate:
                if cve_id and not self.validate_cve_id(cve_id):
                    raise MappingError(f"无效的CVE ID格式: {cve_id}")

            self.mappings[fingerprint] = FingerprintCVEMapping(
                fingerprint=fingerprint,
                cve_id=cve_id,
                description=description
            )
            added_count += 1

        if added_count > 0:
            self.save()

        return added_count

    def remove_mapping(self, fingerprint: str) -> bool:
        """
        删除指纹-CVE映射

        Args:
            fingerprint: 指纹

        Returns:
            是否成功
        """
        if fingerprint in self.mappings:
            del self.mappings[fingerprint]
            return self.save()
        return False

    def bulk_remove_mappings(self, fingerprints: List[str]) -> int:
        """
        批量删除映射关系

        Args:
            fingerprints: 指纹列表

        Returns:
            成功删除的数量
        """
        removed_count = 0

        for fingerprint in fingerprints:
            if fingerprint in self.mappings:
                del self.mappings[fingerprint]
                removed_count += 1

        if removed_count > 0:
            self.save()

        return removed_count

    def get_cve(self, fingerprint: str) -> Optional[str]:
        """
        根据指纹获取对应的CVE编号

        Args:
            fingerprint: 指纹

        Returns:
            CVE编号，如果不存在则返回None
        """
        mapping = self.mappings.get(fingerprint)
        return mapping.cve_id if mapping else None

    def get_mapping(self, fingerprint: str) -> Optional[FingerprintCVEMapping]:
        """
        获取完整的映射信息

        Args:
            fingerprint: 指纹

        Returns:
            FingerprintCVEMapping对象，如果不存在则返回None
        """
        return self.mappings.get(fingerprint)

    def get_all_mappings(self) -> List[FingerprintCVEMapping]:
        """
        获取所有映射关系

        Returns:
            所有映射的列表
        """
        return list(self.mappings.values())

    def search_by_cve(self, cve_id: str) -> List[FingerprintCVEMapping]:
        """
        根据CVE编号查找所有匹配的指纹

        Args:
            cve_id: CVE编号

        Returns:
            匹配的映射列表
        """
        return [
            mapping for mapping in self.mappings.values()
            if mapping.cve_id and mapping.cve_id.upper() == cve_id.upper()
        ]


# 全局管理器实例
_default_manager: Optional[FingerprintCVEManager] = None


def get_manager() -> FingerprintCVEManager:
    """获取默认的全局管理器实例"""
    global _default_manager
    if _default_manager is None:
        _default_manager = FingerprintCVEManager()
    return _default_manager


__all__ = [
    "FingerprintCVEMapping",
    "FingerprintCVEManager",
    "get_manager",
    "MappingError",
]
