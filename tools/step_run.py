"""带重试与分级的 CI 步骤运行器。

为什么需要它：CF 步骤长期 `continue-on-error`，令牌过期或 API 抖动时构建照样绿，
线上继续跑旧规则 —— 这是最安静的一类事故。这里把步骤分成两级：

  required  核心链路（Pages/Worker/Gateway 部署）：重试后仍失败 → 退出码 1，构建红，触发 Alert。
  soft      辅助任务（剪枝/对齐/AE/AI/体检）：失败不红的理由必须写进 out/deploy_warnings.json，
            由最后的汇总步骤统一 ::warning::，能看见但不断供。

CF_API_TOKEN / CF_TOKEN 都没配置时统一跳过（视为未启用 CF），不算失败。
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

WARN = pathlib.Path("out/deploy_warnings.json")
BACKOFF = [5, 20, 60]


def have_cf_token():
    return bool(os.environ.get("CF_API_TOKEN") or os.environ.get("CF_TOKEN"))


def record(name, detail):
    WARN.parent.mkdir(parents=True, exist_ok=True)
    data = []
    if WARN.exists():
        try:
            data = json.loads(WARN.read_text(encoding="utf-8"))
        except Exception:
            data = []
    data.append({"step": name, "detail": detail[:300], "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
    WARN.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--mode", choices=["required", "soft"], default="required")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        print("step_run: 缺少命令", file=sys.stderr)
        return 1

    if not have_cf_token():
        print(f"[{a.name}] 未配置 CF 令牌，跳过")
        return 0

    attempts = max(1, a.retries + 1)
    for i in range(attempts):
        if i:
            wait = BACKOFF[min(i - 1, len(BACKOFF) - 1)]
            print(f"[{a.name}] 第 {i+1}/{attempts} 次尝试（等待 {wait}s）")
            time.sleep(wait)
        r = subprocess.run(cmd, check=False)
        if r.returncode == 0:
            print(f"[{a.name}] OK")
            return 0
        print(f"[{a.name}] 失败，退出码 {r.returncode}")

    detail = f"{' '.join(cmd)} 连续 {attempts} 次失败"
    if a.mode == "soft":
        record(a.name, detail)
        print(f"::warning::{a.name} 失败（{attempts} 次），已记入部署警告：{detail}")
        return 0
    print(f"::error::{a.name} 失败（{attempts} 次）：{detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
