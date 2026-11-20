#!/usr/bin/env python3
"""路径层（L2）产物体检：源表合法、三端文件一致、MITM 主机合规、正则可编译。"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "subs" / "paths"
FILES = {"core": ["noas-path.sgmodule", "noas-path.plugin", "noas-path.conf", "paths.txt", "mitm.txt"],
         "full": ["noas-path.sgmodule", "noas-path.plugin", "noas-path.conf", "paths.txt", "mitm.txt"]}
HOST_RE = re.compile(r"^[a-z0-9*][a-z0-9*.-]*$")
fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


def read_tsv():
    rows = []
    for line in (ROOT / "lists" / "ad_paths.tsv").read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        check(len(parts) == 6, f"源表列数不为 6：{line!r}")
        if len(parts) != 6:
            continue
        host, path, action, app, note, tier = parts
        check(action in ("reject", "reject-dict"), f"动作不合法：{line!r}")
        check(tier in ("core", "full"), f"tier 不合法：{line!r}")
        check(path.startswith("/"), f"path 不以 / 开头：{line!r}")
        check(".*" not in path, f"出现 .* 通配：{line!r}")
        check(tier != "core" or host.strip(), f"core 档必须锚定主机：{line!r}")
        rows.append(dict(host=host.strip(), path=path, tier=tier))
    return rows


def main():
    rows = read_tsv()
    manifest = json.loads((OUT / "manifest.json").read_text(encoding="utf-8"))
    for tier in ("core", "full"):
        for f in FILES[tier]:
            check((OUT / tier / f).exists(), f"缺文件 subs/paths/{tier}/{f}")
        expect = sum(1 for r in rows if r["tier"] == "core" or tier == "full")
        check(manifest["tiers"][tier]["rules"] == expect,
              f"{tier} 条数不一致：manifest {manifest['tiers'][tier]['rules']} vs 源表 {expect}")
        mitm = [h.strip() for h in (OUT / tier / "mitm.txt").read_text(encoding="utf-8").splitlines() if h.strip()]
        check(len(mitm) == manifest["tiers"][tier]["mitm"], f"{tier} MITM 数不一致")
        for h in mitm:
            check(bool(HOST_RE.match(h)), f"{tier} MITM 主机不合法：{h}")
        for f, sep in (("noas-path.sgmodule", " "), ("noas-path.plugin", " - "), ("noas-path.conf", " url ")):
            text = (OUT / tier / f).read_text(encoding="utf-8")
            body = text.split("hostname = %APPEND%", 1)[0]
            rules = [l for l in body.splitlines() if l.startswith("^https?") or l.startswith("^https")]
            check(len(rules) == expect, f"{tier}/{f} 规则行数 {len(rules)} != {expect}")
            for l in rules:
                pattern = l.split(sep, 1)[0]
                try:
                    re.compile(pattern)
                except re.error as e:
                    check(False, f"{tier}/{f} 正则编译失败 {e}: {pattern}")
    ubo = ROOT / "subs" / "paths" / "ubo" / "noas-ubo.txt"
    check(ubo.exists(), "缺 uBO 规则文件")
    if ubo.exists():
        for i, line in enumerate(ubo.read_text(encoding="utf-8").splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("!"):
                continue
            if "##" in s:
                host, sel = s.split("##", 1)
                check(bool(host) and bool(sel), f"ubo 第 {i} 行选择器为空：{s}")
            else:
                check(s.startswith("||") and s.endswith("^"), f"ubo 第 {i} 行网络规则格式异常：{s}")
    if fails:
        print("\n".join("FAIL " + f for f in fails))
        sys.exit(1)
    print(f"paths PASS · core {manifest['tiers']['core']['rules']} 条 / full {manifest['tiers']['full']['rules']} 条 · MITM {manifest['tiers']['full']['mitm']} 主机")


if __name__ == "__main__":
    main()
