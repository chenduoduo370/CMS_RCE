#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
指纹与CVE映射管理模块
支持自定义指纹（MD5值等）与CVE编号的一一对应关系
"""

import os
import json
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict


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
            config_file: 配置文件路径，默认为当前目录下的 fingerprint_cve_mapping.json
        """
        if config_file is None:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            config_file = os.path.join(current_dir, "fingerprint_cve_mapping.json")
        
        self.config_file = config_file
        self.mappings: Dict[str, FingerprintCVEMapping] = {}
        self.load()
    
    def load(self) -> None:
        """从文件加载映射关系"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.mappings = {
                        fp: FingerprintCVEMapping(**item)
                        for fp, item in data.items()
                    }
            except Exception:
                # 如果加载失败，使用空字典
                self.mappings = {}
        else:
            self.mappings = {}
    
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
        except Exception:
            return False
    
    def add_mapping(self, fingerprint: str, cve_id: Optional[str] = None, description: Optional[str] = None) -> bool:
        """
        添加或更新指纹-CVE映射
        
        Args:
            fingerprint: 指纹（如MD5值）
            cve_id: CVE编号，可以为None
            description: 描述信息（可选）
        
        Returns:
            是否成功
        """
        if not fingerprint:
            return False
        
        self.mappings[fingerprint] = FingerprintCVEMapping(
            fingerprint=fingerprint,
            cve_id=cve_id,
            description=description
        )
        return self.save()
    
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
]

