"""日志分析：多维度统计分析。

分析维度参考成熟日志分析工具的常见做法，覆盖：
总览指标、时间序列、状态码分布、Top URL、Top IP（含归属地）、
客户端分布（浏览器/系统/设备/爬虫）、来源分布、请求方法、
错误明细、可疑请求识别、访问热力图。

所有统计基于一次解析后的记录列表，惰性计算并缓存结果。
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Optional, Sequence
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

from core.ipgeo import IPGeoResolver
from core.parser import LogRecord
from core.useragent import parse_ua

# 状态码分组
_STATUS_GROUPS = (
    ("2xx", "成功", 200, 299),
    ("3xx", "重定向", 300, 399),
    ("4xx", "客户端错误", 400, 499),
    ("5xx", "服务端错误", 500, 599),
)


def _pct(part: int | float, whole: int | float) -> float:
    if not whole:
        return 0.0
    return round(float(part) / float(whole) * 100, 2)


def _top(counter: Counter, limit: int) -> list[tuple[str, int]]:
    return counter.most_common(limit)


class LogAnalyzer:
    """对一批日志记录做多维度分析。"""

    def __init__(
        self,
        records: Sequence[LogRecord],
        tz: ZoneInfo | None = None,
        geo: IPGeoResolver | None = None,
        pv_exclude_static: bool = True,
    ) -> None:
        self.records = list(records)
        self.tz = tz or ZoneInfo("Asia/Shanghai")
        self.geo = geo or IPGeoResolver(enabled=False)
        self.pv_exclude_static = pv_exclude_static
        self._ua_cache: dict[str, dict] = {}
        self._cache: dict[str, object] = {}

    # ------------------------------------------------------------------ 内部工具

    def _ua(self, ua: str) -> dict:
        if ua not in self._ua_cache:
            self._ua_cache[ua] = parse_ua(ua)
        return self._ua_cache[ua]

    def _is_pv(self, record: LogRecord) -> bool:
        """PV 统计：可选排除静态资源请求。"""
        if self.pv_exclude_static and record.is_static:
            return False
        return True

    # ------------------------------------------------------------------ 总览

    def overview(self) -> dict:
        if "overview" in self._cache:
            return self._cache["overview"]  # type: ignore[return-value]

        total = len(self.records)
        if total == 0:
            result = {
                "requests": 0, "pv": 0, "uv": 0, "bandwidth": 0, "avg_size": 0.0,
                "errors": 0, "error_rate": 0.0, "bot_requests": 0, "bot_rate": 0.0,
                "human_requests": 0, "unique_urls": 0, "start_time": "", "end_time": "",
                "duration_hours": 0.0, "qps": 0.0, "status_groups": {},
            }
            self._cache["overview"] = result
            return result

        ips: set[str] = set()
        urls: set[str] = set()
        pv = bandwidth = errors = bots = 0
        first: datetime | None = None
        last: datetime | None = None
        groups = {key: 0 for key, _, _, _ in _STATUS_GROUPS}

        for record in self.records:
            ips.add(record.ip)
            urls.add(record.path)
            if self._is_pv(record):
                pv += 1
            bandwidth += record.size
            if record.is_error:
                errors += 1
            if self._ua(record.ua)["is_bot"]:
                bots += 1
            for key, _, low, high in _STATUS_GROUPS:
                if low <= record.status <= high:
                    groups[key] += 1
                    break
            if first is None or record.time < first:
                first = record.time
            if last is None or record.time > last:
                last = record.time

        span_seconds = max((last - first).total_seconds(), 1.0) if first and last else 1.0
        result = {
            "requests": total,
            "pv": pv,
            "uv": len(ips),
            "bandwidth": bandwidth,
            "avg_size": round(bandwidth / total, 2),
            "errors": errors,
            "error_rate": _pct(errors, total),
            "bot_requests": bots,
            "bot_rate": _pct(bots, total),
            "human_requests": total - bots,
            "unique_urls": len(urls),
            "start_time": first.strftime("%Y-%m-%d %H:%M:%S") if first else "",
            "end_time": last.strftime("%Y-%m-%d %H:%M:%S") if last else "",
            "duration_hours": round(span_seconds / 3600, 2),
            "qps": round(total / span_seconds, 4),
            "status_groups": groups,
        }
        self._cache["overview"] = result
        return result

    # ------------------------------------------------------------------ 时间序列

    def timeseries(self, interval: str = "hour") -> dict:
        cache_key = f"timeseries:{interval}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        if interval not in ("hour", "day", "minute", "month"):
            interval = "hour"
        fmt = {
            "minute": "%Y-%m-%d %H:%M",
            "hour": "%Y-%m-%d %H:00",
            "day": "%Y-%m-%d",
            "month": "%Y-%m",
        }[interval]

        buckets: dict[str, dict] = {}
        for record in self.records:
            key = record.time.strftime(fmt)
            bucket = buckets.get(key)
            if bucket is None:
                bucket = {"requests": 0, "pv": 0, "bandwidth": 0, "errors": 0, "ips": set()}
                buckets[key] = bucket
            bucket["requests"] += 1
            if self._is_pv(record):
                bucket["pv"] += 1
            bucket["bandwidth"] += record.size
            if record.is_error:
                bucket["errors"] += 1
            bucket["ips"].add(record.ip)

        keys = sorted(buckets.keys())
        # 补齐缺失的时间点，保证图表连续
        if keys:
            keys = self._fill_gaps(keys, interval)
        points = []
        for key in keys:
            bucket = buckets.get(key)
            if bucket is None:
                points.append({"time": key, "requests": 0, "pv": 0, "uv": 0,
                               "bandwidth": 0, "errors": 0})
                continue
            points.append({
                "time": key,
                "requests": bucket["requests"],
                "pv": bucket["pv"],
                "uv": len(bucket["ips"]),
                "bandwidth": bucket["bandwidth"],
                "errors": bucket["errors"],
            })

        result = {"interval": interval, "points": points}
        self._cache[cache_key] = result
        return result

    def _fill_gaps(self, keys: list[str], interval: str) -> list[str]:
        """在首尾之间补齐缺失的时间点。"""
        fmt = {
            "minute": "%Y-%m-%d %H:%M",
            "hour": "%Y-%m-%d %H:00",
            "day": "%Y-%m-%d",
            "month": "%Y-%m",
        }[interval]
        try:
            start = datetime.strptime(keys[0], fmt)
            end = datetime.strptime(keys[-1], fmt)
        except ValueError:
            return keys
        step = {
            "minute": timedelta(minutes=1),
            "hour": timedelta(hours=1),
            "day": timedelta(days=1),
            "month": timedelta(days=31),
        }[interval]

        filled: list[str] = []
        cursor = start
        guard = 0
        while cursor <= end and guard < 5000:
            filled.append(cursor.strftime(fmt))
            if interval == "month":
                cursor = (cursor.replace(day=28) + timedelta(days=4)).replace(day=1)
            else:
                cursor += step
            guard += 1
        return filled

    # ------------------------------------------------------------------ 状态码

    def status_codes(self) -> dict:
        if "status_codes" in self._cache:
            return self._cache["status_codes"]  # type: ignore[return-value]

        counts: Counter = Counter()
        bandwidth: Counter = Counter()
        for record in self.records:
            counts[record.status] += 1
            bandwidth[record.status] += record.size

        total = len(self.records)
        items = [
            {
                "code": code,
                "count": count,
                "percent": _pct(count, total),
                "bandwidth": bandwidth[code],
            }
            for code, count in counts.most_common()
        ]
        groups = []
        for key, label, low, high in _STATUS_GROUPS:
            count = sum(c for code, c in counts.items() if low <= code <= high)
            groups.append({"group": key, "label": label, "count": count,
                           "percent": _pct(count, total)})
        result = {"total": total, "groups": groups, "items": items}
        self._cache["status_codes"] = result
        return result

    # ------------------------------------------------------------------ Top URL

    def top_urls(self, limit: int = 20) -> list[dict]:
        cache_key = f"top_urls:{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        stats: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "bandwidth": 0, "errors": 0, "codes": Counter(), "ips": set()}
        )
        for record in self.records:
            item = stats[record.path]
            item["count"] += 1
            item["bandwidth"] += record.size
            item["codes"][record.status] += 1
            item["ips"].add(record.ip)
            if record.is_error:
                item["errors"] += 1

        total = len(self.records)
        ranked = sorted(stats.items(), key=lambda kv: kv[1]["count"], reverse=True)[:limit]
        result = [
            {
                "path": path,
                "requests": data["count"],
                "percent": _pct(data["count"], total),
                "bandwidth": data["bandwidth"],
                "avg_size": round(data["bandwidth"] / data["count"], 2) if data["count"] else 0,
                "errors": data["errors"],
                "unique_ips": len(data["ips"]),
                "status_codes": dict(data["codes"].most_common(5)),
            }
            for path, data in ranked
        ]
        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------ Top IP

    def top_ips(self, limit: int = 20, with_geo: bool = True) -> list[dict]:
        cache_key = f"top_ips:{limit}:{with_geo}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        stats: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "bandwidth": 0, "errors": 0, "paths": set(),
                     "ua": "", "last": None}
        )
        for record in self.records:
            item = stats[record.ip]
            item["count"] += 1
            item["bandwidth"] += record.size
            item["paths"].add(record.path)
            if record.is_error:
                item["errors"] += 1
            if not item["ua"] and record.ua:
                item["ua"] = record.ua
            if item["last"] is None or record.time > item["last"]:
                item["last"] = record.time

        total = len(self.records)
        ranked = sorted(stats.items(), key=lambda kv: kv[1]["count"], reverse=True)[:limit]
        ips = [ip for ip, _ in ranked]
        locations = self.geo.resolve_many(ips) if with_geo else {}

        result = []
        for ip, data in ranked:
            ua_info = self._ua(data["ua"])
            result.append({
                "ip": ip,
                "requests": data["count"],
                "percent": _pct(data["count"], total),
                "bandwidth": data["bandwidth"],
                "errors": data["errors"],
                "unique_paths": len(data["paths"]),
                "location": locations.get(ip, "未解析" if with_geo else "未启用"),
                "browser": ua_info["browser"],
                "os": ua_info["os"],
                "device": ua_info["device"],
                "is_bot": ua_info["is_bot"],
                "bot_name": ua_info["bot_name"],
                "last_time": data["last"].strftime("%Y-%m-%d %H:%M:%S") if data["last"] else "",
            })
        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------ 客户端

    def clients(self) -> dict:
        if "clients" in self._cache:
            return self._cache["clients"]  # type: ignore[return-value]

        browsers: Counter = Counter()
        systems: Counter = Counter()
        devices: Counter = Counter()
        bot_names: Counter = Counter()
        known_ua: Counter = Counter()

        for record in self.records:
            info = self._ua(record.ua)
            browsers[info["browser"]] += 1
            systems[info["os"]] += 1
            devices[info["device"]] += 1
            if info["is_bot"]:
                bot_names[info["bot_name"] or "其他爬虫"] += 1
            if record.ua:
                known_ua[record.ua] += 1

        total = len(self.records)
        return {
            "total": total,
            "browsers": self._dist(browsers, total),
            "systems": self._dist(systems, total),
            "devices": self._dist(devices, total),
            "bots": self._dist(bot_names, total),
            "top_user_agents": [
                {"ua": ua, "count": count, "percent": _pct(count, total)}
                for ua, count in known_ua.most_common(10)
            ],
        }

    @staticmethod
    def _dist(counter: Counter, total: int) -> list[dict]:
        return [
            {"name": name, "count": count, "percent": _pct(count, total)}
            for name, count in counter.most_common()
        ]

    # ------------------------------------------------------------------ 来源

    def referers(self, limit: int = 20) -> dict:
        cache_key = f"referers:{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        domains: Counter = Counter()
        direct = internal = external = 0
        host = ""
        for record in self.records:
            if record.vhost and not host:
                host = record.vhost

        for record in self.records:
            ref = record.referer.strip()
            if not ref:
                direct += 1
                continue
            try:
                parsed = urlparse(ref if "://" in ref else "http://" + ref)
                domain = parsed.netloc or parsed.path.split("/")[0]
            except ValueError:
                domain = ref[:80]
            if not domain:
                direct += 1
                continue
            if host and host.split(":")[0] in domain:
                internal += 1
            else:
                external += 1
                domains[domain] += 1

        total = len(self.records)
        return {
            "total": total,
            "direct": direct,
            "direct_percent": _pct(direct, total),
            "internal": internal,
            "external": external,
            "items": [
                {"domain": domain, "count": count, "percent": _pct(count, total)}
                for domain, count in domains.most_common(limit)
            ],
        }

    # ------------------------------------------------------------------ 方法

    def methods(self) -> list[dict]:
        if "methods" in self._cache:
            return self._cache["methods"]  # type: ignore[return-value]
        counter: Counter = Counter()
        bandwidth: Counter = Counter()
        for record in self.records:
            counter[record.method] += 1
            bandwidth[record.method] += record.size
        total = len(self.records)
        result = [
            {"method": method, "count": count, "percent": _pct(count, total),
             "bandwidth": bandwidth[method]}
            for method, count in counter.most_common()
        ]
        self._cache["methods"] = result
        return result

    # ------------------------------------------------------------------ 错误

    def errors(self, limit: int = 50) -> dict:
        cache_key = f"errors:{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        by_url: dict[str, dict] = defaultdict(lambda: {"count": 0, "codes": Counter(), "ips": set()})
        by_code: Counter = Counter()
        by_ip: Counter = Counter()
        recent: list[dict] = []

        for record in self.records:
            if not record.is_error:
                continue
            item = by_url[record.path]
            item["count"] += 1
            item["codes"][record.status] += 1
            item["ips"].add(record.ip)
            by_code[record.status] += 1
            by_ip[record.ip] += 1
            recent.append({
                "time": record.time.strftime("%Y-%m-%d %H:%M:%S"),
                "ip": record.ip,
                "status": record.status,
                "path": record.path,
                "ua": record.ua[:120],
            })

        recent.sort(key=lambda item: item["time"], reverse=True)
        ranked_urls = sorted(by_url.items(), key=lambda kv: kv[1]["count"], reverse=True)[:limit]
        total_errors = sum(by_code.values())

        top_error_ips = by_ip.most_common(10)
        location_map = self.geo.resolve_many([ip for ip, _ in top_error_ips])

        result = {
            "total": total_errors,
            "by_code": [
                {"code": code, "count": count, "percent": _pct(count, total_errors)}
                for code, count in by_code.most_common()
            ],
            "by_url": [
                {
                    "path": path,
                    "count": data["count"],
                    "codes": dict(data["codes"].most_common()),
                    "unique_ips": len(data["ips"]),
                }
                for path, data in ranked_urls
            ],
            "top_ips": [
                {"ip": ip, "count": count, "location": location_map.get(ip, "未知")}
                for ip, count in top_error_ips
            ],
            "recent": recent[:limit],
        }
        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------ 可疑请求

    def suspicious(self, limit: int = 50) -> list[dict]:
        cache_key = f"suspicious:{limit}"
        if cache_key in self._cache:
            return self._cache[cache_key]  # type: ignore[return-value]

        hits: dict[str, dict] = defaultdict(lambda: {"count": 0, "ips": set(), "codes": Counter()})
        for record in self.records:
            if not record.is_suspicious:
                continue
            item = hits[record.path]
            item["count"] += 1
            item["ips"].add(record.ip)
            item["codes"][record.status] += 1

        ranked = sorted(hits.items(), key=lambda kv: kv[1]["count"], reverse=True)[:limit]
        result = [
            {
                "path": path,
                "count": data["count"],
                "unique_ips": len(data["ips"]),
                "sample_ips": list(data["ips"])[:3],
                "status_codes": dict(data["codes"].most_common(3)),
            }
            for path, data in ranked
        ]
        self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------ 热力图

    def heatmap(self) -> dict:
        """星期 × 小时 的访问热力图。"""
        if "heatmap" in self._cache:
            return self._cache["heatmap"]  # type: ignore[return-value]

        matrix = [[0] * 24 for _ in range(7)]
        for record in self.records:
            matrix[record.time.weekday()][record.time.hour] += 1

        max_value = max((max(row) for row in matrix), default=0)
        result = {
            "hours": list(range(24)),
            "weekdays": ["周一", "周二", "周三", "周四", "周五", "周六", "周日"],
            "matrix": matrix,
            "max": max_value,
        }
        self._cache["heatmap"] = result
        return result

    # ------------------------------------------------------------------ 汇总

    def analyze_all(self, top_limit: int = 20) -> dict:
        """一次性输出全部维度，供 API/前端使用。"""
        return {
            "overview": self.overview(),
            "status_codes": self.status_codes(),
            "timeseries": self.timeseries("hour"),
            "top_urls": self.top_urls(top_limit),
            "top_ips": self.top_ips(top_limit),
            "clients": self.clients(),
            "referers": self.referers(top_limit),
            "methods": self.methods(),
            "errors": self.errors(50),
            "suspicious": self.suspicious(30),
            "heatmap": self.heatmap(),
        }


def analyze(records: Sequence[LogRecord], **kwargs) -> dict:
    """便捷入口：对记录做完整分析。"""
    top_limit = kwargs.pop("top_limit", 20)
    return LogAnalyzer(records, **kwargs).analyze_all(top_limit)
