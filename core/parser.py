"""日志解析：把 Nginx / Apache 访问日志解析为结构化记录。

相比按空格切分的做法，这里使用正则匹配整行结构，因此能正确处理
User-Agent 中含空格、Referer 缺失、请求行为 "-"、以及带 vhost 前缀等常见情况。
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional
from zoneinfo import ZoneInfo

# 支持的时间格式（末尾带时区偏移，或退化为本地时间）
_TIME_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S")

# 整行匹配：可选 vhost | IP | ident | user | [时间] | "请求行" | 状态码 | 大小 | 可选 "Referer" "UA" ...
_LINE_RE = re.compile(
    r"^(?:(?P<vhost>[A-Za-z0-9._:\-]+)\s+)?"
    r"(?P<ip>[0-9A-Fa-f:.]+)\s+"
    r"(?P<ident>\S+)\s+(?P<user>\S+)\s+"
    r"\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<request>[^"]*)"\s+'
    r"(?P<status>\d{3}|-)\s+"
    r"(?P<size>\d+|-)\s*"
    r'(?:"(?P<referer>[^"]*)"\s*)?'
    r'(?:"(?P<ua>[^"]*)"\s*)?'
    r'(?:"(?P<trailing>[^"]*)"\s*)?'
    r".*$"
)

# 静态资源后缀：用于 PV 过滤（统计"有效页面浏览"时排除）
STATIC_SUFFIXES = (
    ".css", ".js", ".map", ".json", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".svg", ".ico", ".bmp", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".avi", ".mov", ".pdf", ".zip", ".gz", ".tar",
    ".rar", ".7z", ".apk", ".dmg", ".exe", ".txt", ".xml", ".rss",
)

# 常见错误页/探测路径特征（用于安全分析）
SENSITIVE_PATTERNS = (
    ".env", ".git/", "wp-admin", "wp-login", "phpmyadmin", "admin.php",
    "xmlrpc.php", "config.php", "backup", ".sql", ".bak", "passwd",
    "shell.php", "eval(", "etc/passwd", "../", "..%2f", "cgi-bin",
)


class LogRecord:
    """单条访问日志。"""

    __slots__ = ("ip", "time", "method", "path", "protocol", "status",
                 "size", "referer", "ua", "vhost", "raw_time")

    def __init__(self, ip: str, time: datetime, method: str, path: str,
                 protocol: str, status: int, size: int, referer: str,
                 ua: str, vhost: str, raw_time: str) -> None:
        self.ip = ip
        self.time = time
        self.method = method
        self.path = path
        self.protocol = protocol
        self.status = status
        self.size = size
        self.referer = referer
        self.ua = ua
        self.vhost = vhost
        self.raw_time = raw_time

    @property
    def is_error(self) -> bool:
        return self.status >= 400

    @property
    def is_static(self) -> bool:
        """是否为静态资源请求（用于 PV 过滤）。"""
        lower = self.path.split("?", 1)[0].lower()
        return lower.endswith(STATIC_SUFFIXES)

    @property
    def is_suspicious(self) -> bool:
        """是否命中常见攻击/探测特征。"""
        lower = self.path.lower()
        return any(pat in lower for pat in SENSITIVE_PATTERNS)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "time": self.time.strftime("%Y-%m-%d %H:%M:%S"),
            "method": self.method,
            "path": self.path,
            "protocol": self.protocol,
            "status": self.status,
            "size": self.size,
            "referer": self.referer,
            "ua": self.ua,
            "vhost": self.vhost,
        }


class ParseStats:
    """解析统计，便于向前端反馈日志质量。"""

    def __init__(self) -> None:
        self.total = 0
        self.parsed = 0
        self.failed = 0
        self.skipped_empty = 0
        self.samples_failed: list[str] = []

    @property
    def success_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return round(self.parsed / self.total * 100, 2)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "parsed": self.parsed,
            "failed": self.failed,
            "skipped_empty": self.skipped_empty,
            "success_rate": self.success_rate,
            "samples_failed": self.samples_failed[:5],
        }


def parse_time(raw: str, tz: ZoneInfo) -> Optional[datetime]:
    """解析日志时间并转换为目标时区的感知时间。"""
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if dt.tzinfo is None:
            # 无时区信息：按目标时区解释
            dt = dt.replace(tzinfo=tz)
        return dt.astimezone(tz)
    return None


def parse_line(line: str, tz: ZoneInfo) -> Optional[LogRecord]:
    """解析单行日志；无法解析时返回 None。"""
    match = _LINE_RE.match(line)
    if not match:
        return None

    raw_time = match.group("time")
    time_value = parse_time(raw_time, tz)
    if time_value is None:
        return None

    request = (match.group("request") or "").strip()
    method, path, protocol = "-", "-", "-"
    if request and request != "-":
        parts = request.split(" ")
        if len(parts) >= 1:
            method = parts[0]
        if len(parts) >= 2:
            path = parts[1]
        if len(parts) >= 3:
            protocol = parts[2]

    status_raw = match.group("status")
    try:
        status = int(status_raw)
    except (TypeError, ValueError):
        status = 0

    size_raw = match.group("size")
    size = int(size_raw) if size_raw and size_raw.isdigit() else 0

    return LogRecord(
        ip=match.group("ip"),
        time=time_value,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        size=size,
        referer=_clean(match.group("referer")),
        ua=_clean(match.group("ua")),
        vhost=_clean(match.group("vhost")),
        raw_time=raw_time,
    )


def _clean(value: Optional[str]) -> str:
    if value is None or value == "-":
        return ""
    return value.strip()


def parse_lines(lines: Iterable[str], tz: ZoneInfo | None = None) -> tuple[list[LogRecord], ParseStats]:
    """批量解析日志行，返回记录列表与统计。"""
    tz = tz or ZoneInfo("Asia/Shanghai")
    records: list[LogRecord] = []
    stats = ParseStats()
    for line in lines:
        if not line or not line.strip():
            stats.skipped_empty += 1
            continue
        stats.total += 1
        record = parse_line(line, tz)
        if record is None:
            stats.failed += 1
            if len(stats.samples_failed) < 5:
                stats.samples_failed.append(line[:200])
            continue
        stats.parsed += 1
        records.append(record)
    return records, stats


def parse_text(text: str, tz: ZoneInfo | None = None) -> tuple[list[LogRecord], ParseStats]:
    """解析整段日志文本。"""
    return parse_lines(text.splitlines(), tz)


def detect_format(sample_lines: Iterable[str]) -> str:
    """粗判日志格式，用于前端提示。"""
    for line in sample_lines:
        lowered = line.lower()
        if " - - [" in lowered:
            if lowered.count('"') >= 6:
                return "nginx/apache combined"
            return "nginx/apache common"
        if lowered.startswith("#"):
            continue
    return "unknown"
