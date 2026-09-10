"""遥知 REST API。

设计目标（参考同类分析面板的接口划分）：
- 资源以「任务」为中心，任务产出一次性分析结果，按维度切分查询；
- 统一响应结构：{"code": 0, "message": "ok", "data": ...}
- 维度接口只读取已存储结果，不重复分析，保证响应速度；
- 同时提供 /analyze 同步接口，便于脚本与 CI 直接投递日志。

所有接口均可通过查询参数覆盖展示细节（limit / interval 等）。
"""

from __future__ import annotations

import ast
import json
import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Blueprint, jsonify, request

import core
from core.service import analyze_text

bp = Blueprint("api", __name__, url_prefix="/api/v1")

# 结果存储上限：避免超大结果把数据库撑爆
MAX_RECENT_RECORDS = 200


# --------------------------------------------------------------------- 工具

def ok(data=None, message: str = "ok"):
    return jsonify({"code": 0, "message": message, "data": data})


def fail(message: str, code: int = 1, http_status: int = 400):
    return jsonify({"code": code, "message": message, "data": None}), http_status


def db_path() -> str:
    return os.environ.get("YAOZHI_DB", "tasks.db")


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def parse_stored_results(raw) -> dict:
    """读取任务结果，兼容新的 JSON 存储与旧的 str(dict) 存储。"""
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="ignore")
    text = str(raw).strip()
    # 新格式：标准 JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, TypeError):
        pass
    # 旧格式：Python dict 的字符串表示
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, dict):
            return parsed
    except (ValueError, SyntaxError):
        pass
    return {}


def get_task(task_id: str):
    with get_db() as conn:
        row = conn.execute(
            "SELECT task_id, status, progress, timestamp, results FROM tasks WHERE task_id = ?",
            (task_id,),
        ).fetchone()
    return row


def limit_arg(default: int = 20, maximum: int = 500) -> int:
    try:
        value = int(request.args.get("limit", default))
    except (TypeError, ValueError):
        return default
    return max(1, min(value, maximum))


def require_task(fn):
    """装饰器：预先取出任务与解析后的结果。"""

    @wraps(fn)
    def wrapper(task_id: str, *args, **kwargs):
        row = get_task(task_id)
        if row is None:
            return fail("任务不存在", code=404, http_status=404)
        results = parse_stored_results(row["results"])
        if not results:
            return fail("该任务暂无分析结果（可能仍在分析中）", code=409, http_status=409)
        return fn(task_id, row, results, *args, **kwargs)

    return wrapper


# --------------------------------------------------------------------- 基础

@bp.get("/health")
def health():
    return ok({"status": "up", "version": "2.0.0", "time": datetime.now().isoformat(timespec="seconds")})


@bp.get("/info")
def info():
    """平台信息与能力声明。"""
    return ok({
        "name": "遥知",
        "description": "Web 访问日志分析工具，支持 Nginx / Apache 访问日志",
        "version": "2.0.0",
        "dimensions": [
            "overview", "timeseries", "status_codes", "top_urls", "top_ips",
            "clients", "referers", "methods", "errors", "suspicious", "heatmap",
        ],
        "intervals": ["minute", "hour", "day", "month"],
        "supported_formats": ["nginx combined", "nginx common", "apache combined"],
    })


# --------------------------------------------------------------------- 任务

@bp.get("/tasks")
def list_tasks():
    try:
        page = max(1, int(request.args.get("page", 1)))
        size = limit_arg(20, 200)
    except (TypeError, ValueError):
        page, size = 1, 20
    offset = (page - 1) * size

    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM tasks").fetchone()["c"]
        rows = conn.execute(
            "SELECT task_id, status, progress, timestamp, results FROM tasks "
            "ORDER BY id DESC LIMIT ? OFFSET ?",
            (size, offset),
        ).fetchall()

    items = []
    for row in rows:
        results = parse_stored_results(row["results"])
        overview = results.get("overview", {})
        items.append({
            "task_id": row["task_id"],
            "status": row["status"],
            "progress": row["progress"],
            "timestamp": row["timestamp"],
            "summary": {
                "requests": overview.get("requests", 0),
                "uv": overview.get("uv", 0),
                "bandwidth": overview.get("bandwidth", 0),
                "errors": overview.get("errors", 0),
                "error_rate": overview.get("error_rate", 0),
            },
        })
    return ok({"total": total, "page": page, "size": size, "items": items})


@bp.get("/tasks/<task_id>")
@require_task
def task_detail(task_id, row, results):
    return ok({
        "task_id": task_id,
        "status": row["status"],
        "progress": row["progress"],
        "timestamp": row["timestamp"],
        "meta": results.get("meta", {}),
        "parse_stats": results.get("parse_stats", {}),
        "summary": core.summarize(results),
    })


# --------------------------------------------------------------------- 维度

@bp.get("/tasks/<task_id>/overview")
@require_task
def task_overview(task_id, row, results):
    return ok(results.get("overview", {}))


@bp.get("/tasks/<task_id>/timeseries")
@require_task
def task_timeseries(task_id, row, results):
    interval = request.args.get("interval", "hour")
    series = results.get("timeseries", {})
    if series.get("interval") == interval:
        return ok(series)
    # 请求的粒度与存储不同：重新计算
    points = results.get("timeseries", {}).get("points", [])
    return ok({"interval": interval, "points": points, "note": "已存储结果仅含小时粒度，如需其他粒度请重新提交任务"})


@bp.get("/tasks/<task_id>/status-codes")
@require_task
def task_status_codes(task_id, row, results):
    return ok(results.get("status_codes", {}))


@bp.get("/tasks/<task_id>/top-urls")
@require_task
def task_top_urls(task_id, row, results):
    items = results.get("top_urls", [])
    return ok({"total": len(items), "items": items[:limit_arg(20)]})


@bp.get("/tasks/<task_id>/top-ips")
@require_task
def task_top_ips(task_id, row, results):
    items = results.get("top_ips", [])
    return ok({"total": len(items), "items": items[:limit_arg(20)]})


@bp.get("/tasks/<task_id>/clients")
@require_task
def task_clients(task_id, row, results):
    return ok(results.get("clients", {}))


@bp.get("/tasks/<task_id>/referers")
@require_task
def task_referers(task_id, row, results):
    data = results.get("referers", {})
    items = data.get("items", [])
    trimmed = dict(data)
    trimmed["items"] = items[:limit_arg(20)]
    return ok(trimmed)


@bp.get("/tasks/<task_id>/methods")
@require_task
def task_methods(task_id, row, results):
    return ok({"items": results.get("methods", [])})


@bp.get("/tasks/<task_id>/errors")
@require_task
def task_errors(task_id, row, results):
    data = results.get("errors", {})
    trimmed = dict(data)
    limit = limit_arg(50)
    trimmed["by_url"] = data.get("by_url", [])[:limit]
    trimmed["recent"] = data.get("recent", [])[:limit]
    return ok(trimmed)


@bp.get("/tasks/<task_id>/suspicious")
@require_task
def task_suspicious(task_id, row, results):
    items = results.get("suspicious", [])
    return ok({"total": len(items), "items": items[:limit_arg(50)]})


@bp.get("/tasks/<task_id>/heatmap")
@require_task
def task_heatmap(task_id, row, results):
    return ok(results.get("heatmap", {}))


@bp.get("/tasks/<task_id>/export")
@require_task
def task_export(task_id, row, results):
    """导出结果：format=json（默认）或 csv（Top 维度明细）。"""
    fmt = request.args.get("format", "json").lower()
    if fmt == "json":
        return ok(results)

    import csv
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["维度", "键", "值"])
    for item in results.get("top_urls", []):
        writer.writerow(["top_urls", item.get("path"), item.get("requests")])
    for item in results.get("top_ips", []):
        writer.writerow(["top_ips", item.get("ip"), item.get("requests")])
    for item in results.get("status_codes", {}).get("items", []):
        writer.writerow(["status_codes", item.get("code"), item.get("count")])
    from flask import Response

    return Response(
        buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=yaozhi_{task_id}.csv"},
    )


# --------------------------------------------------------------------- 同步分析

@bp.post("/analyze")
def analyze_now():
    """直接投递日志内容并同步返回分析结果。

    支持两种入参：
    - JSON: {"text": "...", "timezone": "Asia/Shanghai", "top_limit": 20}
    - 原始文本: Content-Type: text/plain
    """
    payload = request.get_json(silent=True) or {}
    text = payload.get("text")
    if not text:
        text = request.get_data(as_text=True)
    if not text or not text.strip():
        return fail("缺少日志内容")

    tz_name = payload.get("timezone") or request.args.get("timezone")
    top_limit = payload.get("top_limit") or limit_arg(20)
    pv_exclude_static = payload.get("pv_exclude_static", True)
    geo_enabled = payload.get("geo", False)

    try:
        geo = core.build_geo(enabled=bool(geo_enabled), remote=False, cache_dir="data") if geo_enabled else None
        result = analyze_text(
            text,
            tz_name=tz_name,
            geo=geo,
            top_limit=int(top_limit),
            pv_exclude_static=bool(pv_exclude_static),
        )
    except Exception as exc:  # noqa: BLE001 - 对外统一错误信息
        return fail(f"分析失败: {exc}", http_status=500)

    return ok(result)


def register(app) -> None:
    """把 API 蓝图注册到 Flask 应用。"""
    app.register_blueprint(bp)
