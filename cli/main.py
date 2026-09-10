"""命令行界面：对单个日志文件做分析并输出报告。

由 YaoZhi.py 调用的两个入口保持不变：painting() 与 cli()。
"""

from __future__ import annotations

import json
import os
from prettytable import PrettyTable

import core

MENU = """
请选择操作：
  1) 查看总览指标
  2) 查看 Top 来源 IP（含归属地）
  3) 查看 Top 访问路径
  4) 查看状态码分布
  5) 查看客户端分布（浏览器 / 系统 / 设备）
  6) 查看错误请求与可疑探测
  7) 导出完整结果为 JSON
  8) 继续分析其他文件
  0) 退出程序
"""


def painting() -> None:
    print(r"""
     __     __        _______     _
     \ \   / /       |___  / |   (_)
      \ \_/ / _  ___   / /| |__  _
       \   / _` |/ _ \ / / | '_ \| |
        | | (_| | (_) / /__| | | | |
        |_|\__,_|\___/_____|_| |_|_|

              遥知 · Web 日志分析
""")


def _print_table(title: str, headers: list[str], rows: list[list]) -> None:
    print(f"\n=== {title} ===")
    table = PrettyTable()
    table.field_names = headers
    for row in rows:
        table.add_row(row)
    print(table)


def _human_size(num: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num < 1024:
            return f"{num:.2f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024
    return f"{num:.2f} PB"


def cli() -> None:
    path = input("*>请输入需要分析的日志文件路径：").strip()
    if not os.path.exists(path):
        print(f"文件不存在：{path}")
        return

    print("正在分析，请稍候…")
    try:
        result = core.analyze_file(path)
    except Exception as exc:  # noqa: BLE001 - CLI 场景直接提示
        print(f"分析失败：{exc}")
        return

    overview = result["overview"]
    stats = result["parse_stats"]
    print(f"\n文件：{result['meta'].get('file', path)}")
    print(f"解析：{stats['parsed']} 条成功 / {stats['failed']} 条失败（成功率 {stats['success_rate']}%）")
    print(f"时间范围：{overview['start_time']} ~ {overview['end_time']}")

    while True:
        print(MENU)
        choice = input("*>请输入操作代码：").strip()

        if choice == "1":
            rows = [
                ["总请求数", overview["requests"]],
                ["独立 IP (UV)", overview["uv"]],
                ["页面浏览 (PV)", overview["pv"]],
                ["总流量", _human_size(overview["bandwidth"])],
                ["平均响应大小", _human_size(overview["avg_size"])],
                ["错误请求", f"{overview['errors']}（{overview['error_rate']}%）"],
                ["爬虫流量占比", f"{overview['bot_rate']}%"],
                ["独立路径数", overview["unique_urls"]],
                ["平均 QPS", overview["qps"]],
            ]
            _print_table("总览指标", ["指标", "数值"], rows)

        elif choice == "2":
            rows = [[ip["ip"], ip["location"], ip["requests"], f"{ip['percent']}%",
                     "爬虫" if ip["is_bot"] else "真人",
                     f"{ip['browser']}/{ip['os']}"] for ip in result["top_ips"]]
            _print_table("Top 来源 IP", ["IP", "归属地", "请求数", "占比", "类型", "客户端"], rows)

        elif choice == "3":
            rows = [[u["path"], u["requests"], f"{u['percent']}%", _human_size(u["bandwidth"]),
                     u["errors"]] for u in result["top_urls"]]
            _print_table("Top 访问路径", ["路径", "请求数", "占比", "流量", "错误数"], rows)

        elif choice == "4":
            rows = [[item["code"], item["count"], f"{item['percent']}%"]
                    for item in result["status_codes"]["items"]]
            _print_table("状态码分布", ["状态码", "次数", "占比"], rows)
            groups = [[g["group"], g["label"], g["count"], f"{g['percent']}%"]
                      for g in result["status_codes"]["groups"]]
            _print_table("分组统计", ["分组", "含义", "次数", "占比"], groups)

        elif choice == "5":
            for key, title in (("browsers", "浏览器"), ("systems", "操作系统"), ("devices", "设备类型")):
                rows = [[item["name"], item["count"], f"{item['percent']}%"]
                        for item in result["clients"][key]]
                _print_table(f"客户端 · {title}", ["名称", "次数", "占比"], rows)
            bots = result["clients"].get("bots") or []
            if bots:
                rows = [[item["name"], item["count"], f"{item['percent']}%"] for item in bots]
                _print_table("识别到的爬虫", ["名称", "次数", "占比"], rows)

        elif choice == "6":
            rows = [[e["path"], e["count"], ",".join(map(str, e["codes"].keys())), e["unique_ips"]]
                    for e in result["errors"]["by_url"]]
            _print_table("错误请求 Top URL", ["路径", "次数", "状态码", "涉及 IP 数"], rows)
            rows = [[s["path"], s["count"], s["unique_ips"]] for s in result["suspicious"]]
            _print_table("可疑探测请求", ["路径", "次数", "来源 IP 数"], rows or [])

        elif choice == "7":
            out = os.path.splitext(os.path.basename(path))[0] + "_分析结果.json"
            with open(out, "w", encoding="utf-8") as fh:
                json.dump(result, fh, ensure_ascii=False, indent=2)
            print(f"已导出：{os.path.abspath(out)}")

        elif choice == "8":
            cli()
            return

        elif choice == "0":
            return

        else:
            print("无效的操作代码，请重新输入。")
