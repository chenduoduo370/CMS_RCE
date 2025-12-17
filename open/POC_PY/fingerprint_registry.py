#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
指纹与 PoC 映射管理模块

核心能力：
- 使用 (file_path, 可选 file_hash) 定义漏洞指纹
- 为每个指纹绑定一个可执行的 PoC 函数
- 根据目标文件的路径 / 哈希值进行匹配，并自动执行最精确匹配的 PoC

匹配优先级：
1. 同时匹配 file_path + file_hash 的指纹（精确匹配）
2. 仅按 file_path 匹配的指纹（路径级匹配）
同一次匹配最多触发一个 PoC，如存在多个“同精度冲突”会抛出异常。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Any


PoCFunc = Callable[[Dict[str, Any]], Any]


@dataclass(frozen=True)
class Fingerprint:
    """单个指纹定义"""
    fp_id: str
    file_path: str
    file_hash: Optional[str]
    poc_function: PoCFunc


class FingerprintRegistry:
    """
    指纹注册与匹配执行管理器。

    使用方式：
        registry = FingerprintRegistry()
        registry.add_fingerprint(
            fp_id="drupal_core_changelog",
            file_path="/core/CHANGELOG.txt",
            file_hash="abcd1234...",   # 可选
            poc_function=run_drupal_poc,
        )

        result = registry.match_and_execute(
            target_file_path="/core/CHANGELOG.txt",
            target_file_hash="abcd1234...",
        )
    """

    def __init__(self) -> None:
        # 用列表保留注册顺序，方便调试与遍历
        self._fingerprints: List[Fingerprint] = []
        # 也维护一个 id -> Fingerprint 的索引，方便后续按 id 查询 / 删除（如有需要）
        self._by_id: Dict[str, Fingerprint] = {}

    # ----------------------------------------------------------------------
    # 注册接口
    # ----------------------------------------------------------------------
    def add_fingerprint(
        self,
        fp_id: str,
        file_path: str,
        file_hash: Optional[str],
        poc_function: PoCFunc,
    ) -> None:
        """
        注册一个新的指纹及其 PoC。

        Args:
            fp_id: 指纹唯一 ID
            file_path: 固有文件路径（必须）
            file_hash: 可选固定哈希（MD5/SHA256 等），更精确匹配时使用
            poc_function: 与该指纹对应的 PoC 可调用对象，签名为 f(target_info: dict) -> Any
        """
        if not isinstance(file_path, str) or not file_path:
            raise ValueError("file_path 必须为非空字符串")
        if fp_id in self._by_id:
            raise ValueError(f"重复的指纹 ID: {fp_id}")
        if not callable(poc_function):
            raise TypeError("poc_function 必须是可调用对象")

        fp = Fingerprint(
            fp_id=fp_id,
            file_path=file_path,
            file_hash=file_hash or None,
            poc_function=poc_function,
        )
        self._fingerprints.append(fp)
        self._by_id[fp_id] = fp

    # ----------------------------------------------------------------------
    # 匹配与执行
    # ----------------------------------------------------------------------
    def _match_candidates(
        self,
        target_file_path: str,
        target_file_hash: Optional[str] = None,
    ) -> Dict[str, List[Fingerprint]]:
        """
        返回按精度分组的候选指纹：
        - "exact": 同时匹配路径和哈希
        - "path": 仅匹配路径
        """
        exact: List[Fingerprint] = []
        path_only: List[Fingerprint] = []

        for fp in self._fingerprints:
            # 路径必须匹配
            if fp.file_path != target_file_path:
                continue

            # 如果指纹定义了 hash，则需要目标也提供 hash 且完全相同
            if fp.file_hash:
                if target_file_hash and fp.file_hash == target_file_hash:
                    exact.append(fp)
                # 指纹有 hash 但目标未提供或者不一致，则视为不匹配
                continue

            # 指纹未定义 hash，则只按路径匹配
            path_only.append(fp)

        return {"exact": exact, "path": path_only}

    def match_and_execute(
        self,
        target_file_path: str,
        target_file_hash: Optional[str] = None,
        extra_target_info: Optional[Dict[str, Any]] = None,
    ) -> Optional[Any]:
        """
        根据目标信息匹配最精确的指纹并执行对应 PoC。

        Args:
            target_file_path: 目标文件路径
            target_file_hash: 目标文件哈希（可选）
            extra_target_info: 额外补充信息（如 IP、端口等），会一并传给 PoC

        Returns:
            PoC 函数的返回值；若未匹配到任何指纹则返回 None。

        Raises:
            RuntimeError: 当出现多个“同精度冲突”匹配时抛出异常。
        """
        if not target_file_path:
            raise ValueError("target_file_path 不能为空")

        candidates = self._match_candidates(target_file_path, target_file_hash)
        exact = candidates["exact"]
        path_only = candidates["path"]

        chosen: Optional[Fingerprint] = None

        # 1. 优先使用 “路径+哈希” 精确匹配
        if exact:
            if len(exact) > 1:
                ids = [fp.fp_id for fp in exact]
                raise RuntimeError(f"存在多个精确匹配指纹（路径+哈希），无法确定唯一 PoC: {ids}")
            chosen = exact[0]
        # 2. 否则，再尝试仅路径匹配
        elif path_only:
            if len(path_only) > 1:
                ids = [fp.fp_id for fp in path_only]
                raise RuntimeError(f"存在多个路径级匹配指纹，无法确定唯一 PoC: {ids}")
            chosen = path_only[0]

        if chosen is None:
            # 未匹配到任何指纹
            return None

        # 组装传给 PoC 的目标信息
        target_info: Dict[str, Any] = {
            "file_path": target_file_path,
            "file_hash": target_file_hash,
            "fingerprint_id": chosen.fp_id,
        }
        if extra_target_info:
            target_info.update(extra_target_info)

        return chosen.poc_function(target_info)


# 默认导出一个全局 registry，方便简单场景直接使用：
default_registry = FingerprintRegistry()


def add_fingerprint(
    fp_id: str,
    file_path: str,
    file_hash: Optional[str],
    poc_function: PoCFunc,
) -> None:
    """
    便捷函数：向默认注册表中添加指纹。
    等价于：default_registry.add_fingerprint(...)
    """
    default_registry.add_fingerprint(fp_id, file_path, file_hash, poc_function)


def match_and_execute(
    target_file_path: str,
    target_file_hash: Optional[str] = None,
    extra_target_info: Optional[Dict[str, Any]] = None,
) -> Optional[Any]:
    """
    便捷函数：在默认注册表中进行匹配并执行 PoC。
    等价于：default_registry.match_and_execute(...)
    """
    return default_registry.match_and_execute(target_file_path, target_file_hash, extra_target_info)


__all__ = [
    "Fingerprint",
    "FingerprintRegistry",
    "default_registry",
    "add_fingerprint",
    "match_and_execute",
    "add_payload_fingerprint",
]


# ----------------------------------------------------------------------
# 便捷封装：按 payload 模块名快速注册指纹
# ----------------------------------------------------------------------
def add_payload_fingerprint(
    fp_id: str,
    file_path: str,
    file_hash: Optional[str],
    module_name: str,
    default_cmd: str = "whoami",
    timeout: int = 10,
) -> None:
    """
    便捷封装：将“固有文件指纹”绑定到现有的 payload 模块。

    Args:
        fp_id: 指纹 ID
        file_path: 固有文件路径
        file_hash: 固定哈希，可为 None
        module_name: payload 模块名（如 CVE_2019_6340）
        default_cmd: 默认命令（可被目标信息中的 cmd 覆盖）
        timeout: 默认超时时间（秒，可被目标信息中的 timeout 覆盖）
    """

    def _poc_func(target_info: dict):
        # 延迟导入，避免循环依赖
        from poc_tool import PayloadManager  # type: ignore

        ip = target_info.get("ip")
        port = target_info.get("port")
        cmd = target_info.get("cmd", default_cmd)
        to = int(target_info.get("timeout", timeout))

        if not ip or not port:
            raise ValueError("指纹 PoC 缺少 ip 或 port 信息")

        ip_port = f"{ip}:{port}"
        manager = PayloadManager(debug=False)
        return manager.send_payload(module_name, ip_port, cmd, timeout=to)

    add_fingerprint(fp_id, file_path, file_hash, _poc_func)


