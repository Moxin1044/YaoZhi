"""分析服务层：串联「读取 → 解析 → 多维分析」，供 Web 后端与 CLI 复用。

对外只暴露少量函数，隐藏解析器与分析器的细节；
流式读取避免把大文件整体载入内存。
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Iterator
from zoneinfo import ZoneInfo

from core.analyzer import LogAnalyzer
from core.ipgeo import IPGeoResolver
from core.parser import ParseStats, parse_lines

DEFAULT_TZ = "Asia/Shanghai"


def iter_lines(path: str | os.PathLike) -> Iterator[str]:
    """流式读取日志文件（容错编码，忽略无法解码的字节）。"""
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.rstrip("\n").rstrip("\r")
            if line:
                yield line


def resolve_tz(name: str | None) -> ZoneInfo:
    """解析时区名，失败时回退到默认时区。"""
    try:
        return ZoneInfo(name or DEFAULT_TZ)
    except Exception:
        return ZoneInfo(DEFAULT_TZ)


def build_geo(
    enabled: bool = True,
    remote: bool = True,
    cache_dir: str | os.PathLike | None = None,
    remote_url: str | None = None,
    timeout: float = 6.0,
) -> IPGeoResolver:
    """构造 IP 归属地解析器（带磁盘缓存）。"""
    cache_file = None
    if cache_dir:
        cache_file = Path(cache_dir) / "ip_geo_cache.json"
    kwargs = {"enabled": enabled, "remote": remote, "cache_file": cache_file, "timeout": timeout}
    if remote_url:
        kwargs["remote_url"] = remote_url
    return IPGeoResolver(**kwargs)


def analyze_lines(
    lines: Iterable[str],
    tz_name: str | None = None,
    geo: IPGeoResolver | None = None,
    top_limit: int = 20,
    pv_exclude_static: bool = True,
) -> dict:
    """分析一组日志行，返回完整结果（含解析统计）。"""
    tz = resolve_tz(tz_name)
    records, stats = parse_lines(lines, tz)
    analyzer = LogAnalyzer(
        records,
        tz=tz,
        geo=geo or IPGeoResolver(enabled=False),
        pv_exclude_static=pv_exclude_static,
    )
    result = analyzer.analyze_all(top_limit)
    result["parse_stats"] = stats.to_dict()
    result["meta"] = {
        "records": len(records),
        "timezone": str(tz),
        "top_limit": top_limit,
        "pv_exclude_static": pv_exclude_static,
    }
    return result


def analyze_file(
    path: str | os.PathLike,
    tz_name: str | None = None,
    geo: IPGeoResolver | None = None,
    top_limit: int = 20,
    pv_exclude_static: bool = True,
) -> dict:
    """分析日志文件。"""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"日志文件不存在: {file_path}")

    result = analyze_lines(
        iter_lines(file_path),
        tz_name=tz_name,
        geo=geo,
        top_limit=top_limit,
        pv_exclude_static=pv_exclude_static,
    )
    result["meta"]["file"] = file_path.name
    result["meta"]["file_size"] = file_path.stat().st_size
    return result


def analyze_text(
    text: str,
    tz_name: str | None = None,
    geo: IPGeoResolver | None = None,
    top_limit: int = 20,
    pv_exclude_static: bool = True,
) -> dict:
    """分析日志文本（用于 API 直接投递内容）。"""
    return analyze_lines(
        text.splitlines(),
        tz_name=tz_name,
        geo=geo,
        top_limit=top_limit,
        pv_exclude_static=pv_exclude_static,
    )


def summarize(result: dict) -> dict:
    """提取结果中的关键指标，便于列表页/通知使用。"""
    overview = result.get("overview", {})
    return {
        "requests": overview.get("requests", 0),
        "uv": overview.get("uv", 0),
        "pv": overview.get("pv", 0),
        "bandwidth": overview.get("bandwidth", 0),
        "errors": overview.get("errors", 0),
        "error_rate": overview.get("error_rate", 0),
        "parse_success_rate": result.get("parse_stats", {}).get("success_rate", 0),
    }


__all__ = [
    "DEFAULT_TZ", "ParseStats", "iter_lines", "resolve_tz", "build_geo",
    "analyze_lines", "analyze_file", "analyze_text", "summarize",
]
