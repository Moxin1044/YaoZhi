"""User-Agent 解析：识别浏览器、操作系统、设备类型与爬虫。

不依赖任何第三方库，规则按优先级排列，避免误判
（例如 Android 设备同时包含 "linux"，iOS 同时包含 "like mac os x"）。
"""

from __future__ import annotations

# 浏览器规则：顺序即优先级（更具体的排前面）
_BROWSER_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("微信内置", ("micromessenger",)),
    ("QQ浏览器", ("qqbrowser",)),
    ("UC浏览器", ("ucbrowser",)),
    ("360浏览器", ("360se", "360ee")),
    ("搜狗浏览器", ("metasr", "sogou")),
    ("Edge", ("edg/", "edge/", "edgios/", "edga/")),
    ("Chrome", ("chrome/", "crios/")),
    ("Firefox", ("firefox/", "fxios/")),
    ("Safari", ("safari/",)),
    ("Opera", ("opr/", "opera")),
    ("Internet Explorer", ("msie", "trident")),
    ("curl", ("curl/",)),
    ("Wget", ("wget/",)),
    ("Python", ("python-requests", "python-urllib", "aiohttp", "httpx")),
    ("Go", ("go-http-client",)),
    ("Java", ("java/", "okhttp")),
)

_OS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("HarmonyOS", ("harmonyos",)),
    ("Android", ("android",)),
    ("iOS", ("iphone", "ipad", "ipod")),
    ("Windows Phone", ("windows phone",)),
    ("Windows", ("windows nt", "windows")),
    ("macOS", ("macintosh", "mac os x")),
    ("Chrome OS", ("cros ",)),
    ("Linux", ("linux", "ubuntu", "debian", "x11")),
)

# 爬虫/机器人特征
_BOT_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Googlebot", ("googlebot", "google-inspectiontool", "apis-google")),
    ("Bingbot", ("bingbot", "msnbot", "bingpreview")),
    ("Baiduspider", ("baiduspider",)),
    ("YandexBot", ("yandexbot", "yandex")),
    ("Sogou Spider", ("sogou web spider", "sogou orion", "sogou")),
    ("360Spider", ("360spider", "haosou")),
    ("搜狗/神马", ("yisouspider", "sm-searchbot")),
    ("Bytespider", ("bytespider",)),
    ("PetalBot", ("petalbot",)),
    ("AhrefsBot", ("ahrefsbot",)),
    ("SemrushBot", ("semrushbot",)),
    ("MJ12bot", ("mj12bot",)),
    ("DotBot", ("dotbot",)),
    ("facebookexternalhit", ("facebookexternalhit", "facebookbot")),
    ("Twitterbot", ("twitterbot",)),
    ("TelegramBot", ("telegrambot",)),
    ("Applebot", ("applebot",)),
    ("DuckDuckBot", ("duckduckbot",)),
    ("GPTBot", ("gptbot", "chatgpt-user", "oai-searchbot")),
    ("ClaudeBot", ("claudebot", "anthropic-ai")),
    ("CCBot", ("ccbot",)),
    ("监控/脚本", (
        "python-requests", "python-urllib", "curl/", "wget/", "go-http-client",
        "aiohttp", "httpx", "java/", "okhttp", "libwww-perl", "lwp-",
        "scrapy", "zgrab", "masscan", "nmap", "nuclei", "gobuster",
    )),
    ("通用爬虫", ("bot", "spider", "crawler", "slurp", "scanner", "headless")),
)


def parse_ua(ua: str) -> dict:
    """解析 User-Agent，返回浏览器/系统/设备/爬虫信息。"""
    if not ua:
        return {
            "browser": "未知", "os": "未知", "device": "未知",
            "is_bot": False, "bot_name": "",
        }
    lowered = ua.lower()

    bot_name = _match(lowered, _BOT_RULES)
    is_bot = bool(bot_name)

    device = "Desktop"
    if any(k in lowered for k in ("ipad", "tablet", "kindle", "playbook")):
        device = "Tablet"
    elif any(k in lowered for k in ("mobile", "iphone", "ipod", "android", "windows phone")):
        device = "Mobile"
    if is_bot:
        device = "Bot"

    return {
        "browser": _match(lowered, _BROWSER_RULES) or "其他",
        "os": _match(lowered, _OS_RULES) or "其他",
        "device": device,
        "is_bot": is_bot,
        "bot_name": bot_name,
    }


def _match(lowered_ua: str, rules) -> str:
    for name, keywords in rules:
        if any(kw in lowered_ua for kw in keywords):
            return name
    return ""
