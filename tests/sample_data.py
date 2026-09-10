"""生成用于测试与演示的样例日志。"""

from __future__ import annotations

import random
from datetime import datetime, timedelta

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # iPhone Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    # Android Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    # 微信内置浏览器
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 MicroMessenger/8.0.47",
    # 搜索引擎爬虫
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    # 脚本客户端
    "python-requests/2.31.0",
    "curl/8.5.0",
]

PATHS = [
    ("/", 200),
    ("/index.html", 200),
    ("/about", 200),
    ("/api/user/profile", 200),
    ("/api/orders?page=1", 200),
    ("/static/css/app.css", 200),
    ("/static/js/vendor.js", 200),
    ("/static/img/logo.png", 200),
    ("/blog/2026/network-security", 200),
    ("/blog/2026/ctf-writeup", 200),
    ("/download/report.pdf", 200),
    ("/old-page", 301),
    ("/not-found-page", 404),
    ("/api/missing", 404),
    ("/images/banner.jpg", 404),
    ("/api/orders/999", 500),
    ("/api/checkout", 500),
    # 可疑探测路径
    ("/.env", 404),
    ("/.git/config", 403),
    ("/wp-admin/setup.php", 404),
    ("/phpmyadmin/index.php", 404),
    ("/shell.php", 404),
]

IPS = [
    "114.114.114.114", "223.5.5.5", "1.1.1.1", "8.8.8.8", "39.156.66.10",
    "192.168.1.10", "192.168.1.23", "10.0.0.5", "127.0.0.1", "180.101.49.12",
]

REFERERS = [
    "", "", "",
    "https://www.google.com/",
    "https://www.baidu.com/s?wd=yaozhi",
    "https://blog.example.com/post/1",
    "https://example.com/",
]


def generate_logs(count: int = 1000, start: datetime | None = None, seed: int = 7) -> list[str]:
    """生成 count 行 nginx combined 格式日志。"""
    rnd = random.Random(seed)
    start = start or datetime(2026, 8, 1, 0, 0, 0)
    lines: list[str] = []

    for i in range(count):
        moment = start + timedelta(seconds=i * 83 + rnd.randint(0, 40))
        path, base_status = rnd.choices(PATHS, weights=[25, 15, 8, 12, 10, 20, 20, 8, 6, 5, 3, 4, 8, 5, 3, 2, 2, 3, 2, 2, 2, 2], k=1)[0]
        status = base_status
        if base_status == 200 and rnd.random() < 0.04:
            status = rnd.choice([206, 304, 401, 403])
        ip = rnd.choices(IPS, weights=[18, 14, 12, 10, 8, 6, 5, 3, 12, 12], k=1)[0]
        ua = rnd.choice(USER_AGENTS)
        referer = rnd.choice(REFERERS)
        size = 0 if status in (304,) else rnd.randint(180, 90_000)
        size_field = "-" if status in (304, 404) and rnd.random() < 0.3 else str(size)
        offset = "+0800"
        stamp = f"{moment.day:02d}/{MONTHS[moment.month - 1]}/{moment.year}:{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d} {offset}"
        method = rnd.choices(["GET", "POST", "HEAD"], weights=[88, 9, 3], k=1)[0]
        lines.append(
            f'{ip} - - [{stamp}] "{method} {path} HTTP/1.1" {status} {size_field} '
            f'"{referer}" "{ua}"'
        )

    return lines


def write_sample(path: str, count: int = 1000) -> str:
    """把样例日志写入文件。"""
    lines = generate_logs(count)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path
