"""日志解析与分析引擎的单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.analyzer import LogAnalyzer          # noqa: E402
from core.ipgeo import IPGeoResolver           # noqa: E402
from core.parser import parse_line, parse_lines, parse_text  # noqa: E402
from core.useragent import parse_ua            # noqa: E402
from tests.sample_data import generate_logs    # noqa: E402

TZ = ZoneInfo("Asia/Shanghai")


# --------------------------------------------------------------------- 解析

def test_parse_combined_line():
    line = ('203.0.113.10 - - [01/Aug/2026:12:34:56 +0800] "GET /index.html HTTP/1.1" '
            '200 5120 "https://www.google.com/" '
            '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36"')
    record = parse_line(line, TZ)
    assert record is not None
    assert record.ip == "203.0.113.10"
    assert record.method == "GET"
    assert record.path == "/index.html"
    assert record.status == 200
    assert record.size == 5120
    assert "google.com" in record.referer
    assert record.time.hour == 12


def test_parse_ua_with_spaces_is_not_broken():
    """UA 含空格时不能被字段切分破坏（旧实现的主要缺陷）。"""
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.3 Safari/605.1.15"
    line = f'198.51.100.7 - - [01/Aug/2026:08:00:00 +0800] "GET /about HTTP/1.1" 200 1024 "-" "{ua}"'
    record = parse_line(line, TZ)
    assert record is not None
    assert record.ua == ua


def test_parse_size_dash_is_zero():
    line = '198.51.100.7 - - [01/Aug/2026:08:00:00 +0800] "GET /x HTTP/1.1" 404 - "-" "curl/8.5.0"'
    record = parse_line(line, TZ)
    assert record is not None
    assert record.size == 0


def test_parse_line_with_vhost_prefix():
    line = ('example.com 203.0.113.10 - - [01/Aug/2026:08:00:00 +0800] '
            '"GET / HTTP/1.1" 200 100 "-" "curl/8.5.0"')
    record = parse_line(line, TZ)
    assert record is not None
    assert record.vhost == "example.com"
    assert record.ip == "203.0.113.10"


def test_parse_timezone_conversion():
    """带 -0700 的时间应换算为目标时区。"""
    line = '203.0.113.10 - - [01/Aug/2026:00:00:00 -0700] "GET / HTTP/1.1" 200 1 "-" "-"'
    record = parse_line(line, TZ)
    assert record is not None
    assert record.time.hour == 15  # -0700 的 0 点 = 北京时间 15 点
    assert record.time.utcoffset().total_seconds() == 8 * 3600


def test_parse_invalid_line_returns_none():
    assert parse_line("this is not a log line", TZ) is None
    assert parse_line("", TZ) is None


def test_parse_stats_counts_failures():
    lines = generate_logs(50) + ["garbage line", "# comment"]
    records, stats = parse_lines(lines, TZ)
    assert stats.total == 52
    assert stats.parsed == 50
    assert stats.failed == 2
    assert len(records) == 50


def test_static_and_suspicious_detection():
    from core.parser import LogRecord
    from datetime import datetime
    static = LogRecord("1.1.1.1", datetime.now(TZ), "GET", "/static/app.css", "HTTP/1.1",
                       200, 10, "", "", "", "")
    assert static.is_static
    attack = LogRecord("1.1.1.1", datetime.now(TZ), "GET", "/.env", "HTTP/1.1",
                       404, 0, "", "", "", "")
    assert attack.is_suspicious
    assert attack.is_error


# --------------------------------------------------------------------- UA

@pytest.mark.parametrize("ua,expected", [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0.0.0 Safari/537.36", "Chrome"),
    ("Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0", "Firefox"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) Version/17.3 Mobile/15E148 Safari/604.1", "Safari"),
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "其他"),
    ("curl/8.5.0", "curl"),
])
def test_ua_browser(ua, expected):
    assert parse_ua(ua)["browser"] == expected


@pytest.mark.parametrize("ua,os_name,device", [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122", "Windows", "Desktop"),
    ("Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/122 Mobile", "Android", "Mobile"),
    ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) Safari/604.1", "iOS", "Mobile"),
    ("Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) Safari/604.1", "iOS", "Tablet"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15", "macOS", "Desktop"),
])
def test_ua_os_and_device(ua, os_name, device):
    info = parse_ua(ua)
    assert info["os"] == os_name
    assert info["device"] == device


@pytest.mark.parametrize("ua,bot", [
    ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Googlebot"),
    ("Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)", "Baiduspider"),
    ("python-requests/2.31.0", "监控/脚本"),
    ("curl/8.5.0", "监控/脚本"),
])
def test_ua_bot_detection(ua, bot):
    info = parse_ua(ua)
    assert info["is_bot"] is True
    assert info["bot_name"] == bot
    assert info["device"] == "Bot"


def test_ua_empty():
    info = parse_ua("")
    assert info["browser"] == "未知"
    assert info["is_bot"] is False


# --------------------------------------------------------------------- 归属地

def test_ip_classify_special_addresses():
    assert IPGeoResolver.classify("127.0.0.1") == "本地"
    assert IPGeoResolver.classify("192.168.1.5") == "内网"
    assert IPGeoResolver.classify("10.0.0.1") == "内网"
    assert IPGeoResolver.classify("172.16.3.4") == "内网"
    assert IPGeoResolver.classify("169.254.1.1") == "链路本地"
    # TEST-NET 属于保留地址，不应被算作内网
    assert IPGeoResolver.classify("203.0.113.10") == "保留地址"
    # 普通公网地址返回 None（交给后续解析）
    assert IPGeoResolver.classify("114.114.114.114") is None
    assert IPGeoResolver.classify("not-an-ip") == "未知"


def test_ipgeo_disabled_returns_unknown():
    geo = IPGeoResolver(enabled=False)
    result = geo.resolve_many(["203.0.113.10"])
    assert result["203.0.113.10"] == "未知"


def test_ipgeo_offline_classifies_private():
    """离线模式下内网/回环地址仍应被正确分类。"""
    geo = IPGeoResolver(enabled=True, remote=False)
    result = geo.resolve_many(["192.168.1.10", "127.0.0.1", "10.1.2.3"])
    assert result["192.168.1.10"] == "内网"
    assert result["127.0.0.1"] == "本地"
    assert result["10.1.2.3"] == "内网"


# --------------------------------------------------------------------- 分析

@pytest.fixture(scope="module")
def analyzer():
    records, stats = parse_text("\n".join(generate_logs(1000)), TZ)
    assert stats.failed == 0
    geo = IPGeoResolver(enabled=True, remote=False)
    return LogAnalyzer(records, tz=TZ, geo=geo)


def test_overview_counts(analyzer):
    data = analyzer.overview()
    assert data["requests"] == 1000
    assert data["uv"] > 0
    assert 0 < data["pv"] <= 1000
    assert data["bandwidth"] > 0
    assert 0 < data["error_rate"] < 100
    assert data["bot_requests"] > 0
    assert data["start_time"] and data["end_time"]
    assert sum(data["status_groups"].values()) == 1000


def test_timeseries_is_continuous(analyzer):
    data = analyzer.timeseries("hour")
    points = data["points"]
    assert len(points) > 1
    assert points[0]["time"] <= points[-1]["time"]
    # 补齐后的时间点应无缺口
    assert all(p["requests"] >= 0 for p in points)
    total = sum(p["requests"] for p in points)
    assert total == 1000


def test_timeseries_daily(analyzer):
    data = analyzer.timeseries("day")
    assert sum(p["requests"] for p in data["points"]) == 1000


def test_status_codes_grouping(analyzer):
    data = analyzer.status_codes()
    assert data["total"] == 1000
    groups = {g["group"]: g["count"] for g in data["groups"]}
    assert sum(groups.values()) == 1000
    codes = {item["code"]: item["count"] for item in data["items"]}
    assert 200 in codes and 404 in codes and 500 in codes
    assert sum(codes.values()) == 1000


def test_top_urls_sorted_and_limited(analyzer):
    data = analyzer.top_urls(5)
    assert len(data) == 5
    counts = [item["requests"] for item in data]
    assert counts == sorted(counts, reverse=True)
    assert all(item["path"].startswith("/") for item in data)


def test_top_ips_with_location(analyzer):
    data = analyzer.top_ips(8)
    assert 0 < len(data) <= 8
    counts = [item["requests"] for item in data]
    assert counts == sorted(counts, reverse=True)
    locations = {item["ip"]: item["location"] for item in data}
    # 内网地址应被识别，不应是"未知"
    assert any(loc in ("内网", "本地") for loc in locations.values())
    assert all(item["browser"] for item in data)


def test_clients_distribution(analyzer):
    data = analyzer.clients()
    assert sum(item["count"] for item in data["browsers"]) == 1000
    assert sum(item["count"] for item in data["devices"]) == 1000
    names = {item["name"] for item in data["browsers"]}
    assert "Chrome" in names
    bots = {item["name"] for item in data["bots"]}
    assert "Googlebot" in bots


def test_referers_breakdown(analyzer):
    data = analyzer.referers()
    assert data["direct"] + data["internal"] + data["external"] == 1000
    assert data["external"] > 0
    assert any("google.com" in item["domain"] for item in data["items"])


def test_methods(analyzer):
    data = analyzer.methods()
    assert sum(item["count"] for item in data) == 1000
    assert data[0]["method"] == "GET"


def test_errors_detail(analyzer):
    data = analyzer.errors(20)
    assert data["total"] > 0
    assert data["recent"]
    assert all(item["status"] >= 400 for item in data["recent"])
    assert data["by_code"]


def test_suspicious_detection(analyzer):
    data = analyzer.suspicious(20)
    paths = {item["path"] for item in data}
    assert "/.env" in paths or "/wp-admin/setup.php" in paths


def test_heatmap_shape(analyzer):
    data = analyzer.heatmap()
    assert len(data["matrix"]) == 7
    assert all(len(row) == 24 for row in data["matrix"])
    assert sum(sum(row) for row in data["matrix"]) == 1000


def test_analyze_all_returns_all_sections(analyzer):
    data = analyzer.analyze_all(10)
    expected = {"overview", "status_codes", "timeseries", "top_urls", "top_ips",
                "clients", "referers", "methods", "errors", "suspicious", "heatmap"}
    assert expected.issubset(data.keys())


def test_empty_input_is_safe():
    analyzer = LogAnalyzer([], tz=TZ)
    overview = analyzer.overview()
    assert overview["requests"] == 0
    assert analyzer.timeseries()["points"] == []
    assert analyzer.status_codes()["items"] == []
    assert analyzer.top_urls() == []
    assert analyzer.heatmap()["max"] == 0
