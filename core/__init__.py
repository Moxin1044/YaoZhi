"""遥知核心分析包。

模块划分：
- parser    日志解析（正则、多格式、时区）
- useragent User-Agent 解析（浏览器/系统/设备/爬虫）
- ipgeo     IP 归属地解析（本地判定 / 本地库 / 远程批量 + 缓存）
- analyzer  多维度统计分析
- service   服务层：读文件 → 解析 → 分析
"""

from core.analyzer import LogAnalyzer, analyze
from core.ipgeo import IPGeoResolver
from core.parser import LogRecord, ParseStats, parse_line, parse_lines, parse_text
from core.service import (
    DEFAULT_TZ,
    analyze_file,
    analyze_lines,
    analyze_text,
    build_geo,
    iter_lines,
    resolve_tz,
    summarize,
)
from core.useragent import parse_ua

__all__ = [
    "LogAnalyzer",
    "analyze",
    "LogRecord",
    "ParseStats",
    "parse_line",
    "parse_lines",
    "parse_text",
    "IPGeoResolver",
    "parse_ua",
    "DEFAULT_TZ",
    "analyze_file",
    "analyze_lines",
    "analyze_text",
    "build_geo",
    "iter_lines",
    "resolve_tz",
    "summarize",
]
