"""IP 归属地解析。

策略（参考同类工具的常见做法）：
1. 本地判定：回环 / 内网 / 链路本地 / 保留地址直接返回，不查外部接口；
2. 本地库：若存在 ip2region xdb 数据文件且已安装依赖，优先离线查询（最快、无需联网）；
3. 远程批量：本地库不可用时调用可配置的接口批量查询，结果写入磁盘缓存；
4. 全部失败：返回「未知」，不阻塞分析流程。

默认对远程查询设置较短超时并缓存结果，避免拖慢整体速度。
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
import time
from pathlib import Path
from typing import Iterable

# 常见远程批量查询接口（可覆盖）；默认使用无需密钥的 ip-api.com
DEFAULT_REMOTE_URL = "http://ip-api.com/batch"
REMOTE_BATCH_SIZE = 100
UNKNOWN = "未知"


# 真正的内网网段（RFC1918 + CGNAT + IPv6 ULA）。
# 注意：ipaddress 的 is_private 还会覆盖 TEST-NET、基准测试段等保留地址，
# 那些不属于"内网"，因此这里显式列举，保证分类语义准确。
_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                "100.64.0.0/10", "fc00::/7")
)


# 34 个省级行政区（短名），用于把归属地文本归一化到地图区域。
# 顺序上把更长的名称放前面，避免"广东/广西"之类的误匹配。
PROVINCES: tuple[str, ...] = (
    "内蒙古", "黑龙江", "新疆", "西藏", "宁夏", "广西",
    "北京", "天津", "河北", "山西", "辽宁", "吉林", "上海", "江苏", "浙江",
    "安徽", "福建", "江西", "山东", "河南", "湖北", "湖南", "广东", "海南",
    "重庆", "四川", "贵州", "云南", "陕西", "甘肃", "青海", "台湾", "香港", "澳门",
)

# 特殊地址（非地理位置）
SPECIAL_LOCATIONS = ("本地", "内网", "链路本地", "组播", "保留地址")


def extract_province(location: str) -> str | None:
    """从归属地文本中提取省级行政区短名；无法识别时返回 None。

    例："中国 山东 济南市" → "山东"；"美国 弗吉尼亚州 Ashburn" → None
    """
    if not location:
        return None
    for province in PROVINCES:
        if province in location:
            return province
    return None


def extract_city(location: str, province: str | None = None) -> str:
    """尽可能从归属地文本中提取城市名（用于省份下的城市明细）。

    例："中国 山东 济南市" → "济南市"；"中国 江苏 南京" → "南京"
    """
    if not location:
        return ""
    parts = [p for p in location.replace(",", " ").split() if p]
    candidates: list[str] = []
    for part in parts:
        if part in ("中国", "China"):
            continue
        if province and province in part:
            continue
        if part.endswith(("省", "自治区", "特别行政区")):
            continue
        candidates.append(part)

    # 优先取带行政后缀的（市/州/盟/地区）
    for candidate in candidates:
        if candidate.endswith(("市", "州", "盟", "地区")):
            return candidate
    # 否则退回最后一个候选（常见于「中国 江苏 南京」这类无后缀形式）
    return candidates[-1] if candidates else ""


class IPGeoResolver:
    """IP 归属地查询器（带缓存与本地库优先策略）。"""

    def __init__(
        self,
        enabled: bool = True,
        remote: bool = True,
        remote_url: str = DEFAULT_REMOTE_URL,
        cache_file: str | os.PathLike | None = None,
        local_xdb: str | os.PathLike | None = None,
        timeout: float = 6.0,
    ) -> None:
        self.enabled = enabled
        self.remote = remote
        self.remote_url = remote_url
        self.timeout = timeout
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()
        self._cache_path = Path(cache_file) if cache_file else None
        self._xdb = None

        if local_xdb and Path(local_xdb).exists():
            self._xdb = self._open_xdb(local_xdb)

        self._load_cache()

    # ------------------------------------------------------------------ 缓存

    def _load_cache(self) -> None:
        if not self._cache_path or not self._cache_path.exists():
            return
        try:
            with self._cache_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._cache = {str(k): str(v) for k, v in data.items()}
        except (OSError, json.JSONDecodeError):
            self._cache = {}

    def save_cache(self) -> None:
        if not self._cache_path:
            return
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open("w", encoding="utf-8") as fh:
                json.dump(self._cache, fh, ensure_ascii=False, indent=0)
        except OSError:
            pass

    # ------------------------------------------------------------------ 本地库

    @staticmethod
    def _open_xdb(path: str | os.PathLike):
        """尝试加载 ip2region 本地库；未安装依赖时返回 None。"""
        try:
            import ip2region.util as util  # type: ignore
            import ip2region.searcher as searcher  # type: ignore
        except Exception:
            return None
        try:
            buffer = util.load_content_from_file(str(path))
            return searcher.new_with_buffer(util.IPv4, buffer)
        except Exception:
            return None

    # ------------------------------------------------------------------ 查询

    @staticmethod
    def classify(ip: str) -> str | None:
        """返回特殊地址的中文描述；普通公网地址返回 None。

        注意判定顺序：ipaddress 会把链路本地、CGNAT 等也视为 private，
        因此先判更具体的类别。
        """
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return UNKNOWN
        if addr.is_loopback:
            return "本地"
        if addr.is_link_local:
            return "链路本地"
        if addr.is_multicast:
            return "组播"
        if any(addr in net for net in _PRIVATE_NETWORKS):
            return "内网"
        if addr.is_reserved or addr.is_unspecified or addr.is_private:
            return "保留地址"
        return None

    def resolve_many(self, ips: Iterable[str]) -> dict[str, str]:
        """批量解析，返回 {ip: 归属地}。"""
        result: dict[str, str] = {}
        if not self.enabled:
            return {ip: UNKNOWN for ip in ips}

        pending: list[str] = []
        for ip in ips:
            special = self.classify(ip)
            if special is not None:
                result[ip] = special
                continue
            cached = self._cache.get(ip)
            if cached:
                result[ip] = cached
                continue
            local = self._lookup_local(ip)
            if local:
                result[ip] = local
                self._cache[ip] = local
                continue
            pending.append(ip)

        if pending and self.remote:
            remote_result = self._lookup_remote(pending)
            for ip in pending:
                location = remote_result.get(ip, UNKNOWN)
                result[ip] = location
                if location != UNKNOWN:
                    self._cache[ip] = location
        else:
            for ip in pending:
                result.setdefault(ip, UNKNOWN)

        with self._lock:
            self._cache.update(result)
        self.save_cache()
        return result

    def _lookup_local(self, ip: str) -> str | None:
        if self._xdb is None:
            return None
        try:
            region = self._xdb.search(ip)
        except Exception:
            return None
        if not region:
            return None
        # ip2region 返回 "国家|区域|省份|城市|ISP"
        parts = [p for p in str(region).split("|") if p and p != "0"]
        if not parts:
            return None
        return " ".join(parts[:3])

    def _lookup_remote(self, ips: list[str]) -> dict[str, str]:
        """调用远程接口批量查询；任何异常都降级为「未知」。"""
        try:
            import requests
        except ImportError:
            return {}

        out: dict[str, str] = {}
        for start in range(0, len(ips), REMOTE_BATCH_SIZE):
            batch = ips[start:start + REMOTE_BATCH_SIZE]
            payload = [{"query": ip, "fields": "status,country,regionName,city,query", "lang": "zh-CN"}
                       for ip in batch]
            try:
                resp = requests.post(self.remote_url, json=payload, timeout=self.timeout)
                if resp.status_code != 200:
                    continue
                for item in resp.json():
                    ip = item.get("query")
                    if not ip:
                        continue
                    if item.get("status") != "success":
                        out[ip] = UNKNOWN
                        continue
                    pieces = [item.get("country"), item.get("regionName"), item.get("city")]
                    out[ip] = " ".join(p for p in pieces if p) or UNKNOWN
            except Exception:
                # 网络不可用/超时：跳过该批，不影响整体分析
                continue
        return out


def resolve_locations(ips: Iterable[str], **kwargs) -> dict[str, str]:
    """便捷函数：一次性解析一批 IP。"""
    return IPGeoResolver(**kwargs).resolve_many(ips)
