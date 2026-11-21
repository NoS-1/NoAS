"""部署健康汇总：把 soft 步骤的失败集中成一条 ::warning:: + step summary。

required 步骤失败会让构建直接红（Alert 会开 Issue）；这里只负责"能看见但不供断"的那部分，
避免辅助任务悄悄坏掉没人知道。
"""
import json
import os
import pathlib

WARN = pathlib.Path("out/deploy_warnings.json")

def main():
    items = []
    if WARN.exists():
        try:
            items = json.loads(WARN.read_text(encoding="utf-8"))
        except Exception:
            items = []
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    lines = ["## 部署健康", ""]
    if not items:
        lines.append("- 全部部署步骤通过，无辅助任务告警")
        print("部署健康：无告警")
    else:
        for w in items:
            line = f"- ⚠️ {w.get('step')}：{w.get('detail')}（{w.get('at')}）"
            lines.append(line)
            print(f"::warning::部署辅助步骤失败：{w.get('step')} — {w.get('detail')}")
    text = "\n".join(lines) + "\n"
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)

if __name__ == "__main__":
    main()
