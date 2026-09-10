#!/usr/bin/env python3
"""生成演示用访问日志。

用法：
    python scripts/gen_sample_log.py [行数] [输出路径]

示例：
    python scripts/gen_sample_log.py 5000 demo.log
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.sample_data import write_sample  # noqa: E402


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    out = sys.argv[2] if len(sys.argv) > 2 else "demo.log"
    path = write_sample(out, count)
    size = Path(path).stat().st_size
    print(f"已生成演示日志：{path}（{count} 行，{size / 1024:.1f} KB）")
    print("可直接在 Web 界面拖入该文件，或执行：")
    print(f"  curl -X POST http://localhost:7100/api/v1/analyze "
          f"-H 'Content-Type: text/plain' --data-binary @{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
