"""生成 Release 说明：三档条数 + 构建时间 + 回滚命令（stdout 即 notes 正文）"""
import datetime
import json
import pathlib

rows = []
for t in ("lite", "mid", "full"):
    m = pathlib.Path(f"subs/{t}/meta.json")
    n = json.loads(m.read_text(encoding="utf-8")).get("count", "?") if m.exists() else "?"
    rows.append(f"- {t}: {n} 条")

print("每日自动重建的规则单包（lite/mid/full + 自建 DoH）")
print()
print(f"版本：{datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M} UTC")
print()
print("\n".join(rows))
print()
bm = pathlib.Path("state/build_manifest.json")
wv = ws = "?"
if bm.exists():
    m = json.loads(bm.read_text(encoding="utf-8"))
    wv, ws = m.get("version", "?"), m.get("sha256", "?")
fp = pathlib.Path("state/benign_fp.json")
fp_txt = ""
if fp.exists():
    d = json.loads(fp.read_text(encoding="utf-8"))
    parts = []
    for t in ("tier1", "tier2", "tier3"):
        if t in d:
            parts.append(f"{t}: n={d[t].get('n')} fp={d[t].get('fp')}")
    fp_txt = "\n误伤回归：" + "｜".join(parts) + "（4444 条业务主域样本，真产物判定）"
print()
print(f"Worker：版本 {wv}／sha {ws}")
print("DoH：`https://noas-cdn.pages.dev/dns-query/{lite,mid,full,auto}`（`/tier` 看条数，`/why?d=` 查判定，`/resolve?name=&type=` 取 JSON）")
print(fp_txt)
