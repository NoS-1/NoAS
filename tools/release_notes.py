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
print("回滚：`gh release download <上一版 tag> -p noas-snapshot.zip`")
