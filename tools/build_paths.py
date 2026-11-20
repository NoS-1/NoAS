#!/usr/bin/env python3
"""把 lists/ad_paths.tsv 编译成三端路径层订阅（Surge / Loon / QuantumultX）。

设计约束：
  1. 只用 reject / reject-dict 两个动作，三端语义一致，且 JSON 接口拿到 {} 不会崩；
  2. core 档每一条都必须锚定具体主机，绝不越界影响别的 App；
  3. full 档才允许空主机（通用路径），范围由 MITM 主机白名单兜住；
  4. 不联网、不猜规则，源文件每行都带 App 与用途注释，出问题能逐条定位。
"""
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TSV = ROOT / "lists" / "ad_paths.tsv"
MITM_EXTRA = ROOT / "lists" / "mitm_hosts.txt"
OUT = ROOT / "subs" / "paths"
HOME = "https://github.com/NoS-1/NoAS"
ACTIONS = {"reject", "reject-dict"}
TIERS = ("core", "full")


def read_rules():
    rules = []
    for line in TSV.read_text(encoding="utf-8").splitlines():
        line = line.strip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            raise SystemExit(f"ad_paths.tsv 列数不对（要 6 列）：{line!r}")
        host, path, action, app, note, tier = parts
        if action not in ACTIONS:
            raise SystemExit(f"动作不合法：{action!r} @ {line!r}")
        if tier not in TIERS:
            raise SystemExit(f"tier 不合法：{tier!r} @ {line!r}")
        if not path.startswith("/"):
            raise SystemExit(f"path 必须以 / 开头：{path!r}")
        if ".*" in path:
            raise SystemExit(f"禁止 .* 通配（误伤源）：{path!r}")
        rules.append(dict(host=host.strip(), path=path, action=action,
                          app=app.strip(), note=note.strip(), tier=tier))
    return rules


def read_mitm_extra():
    hosts = []
    if not MITM_EXTRA.exists():
        return hosts
    for line in MITM_EXTRA.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            hosts.append(line.lower())
    return hosts


def compile_pattern(rule):
    host, path = rule["host"], rule["path"]
    if host:
        host_re = host.replace(".", r"\.")
        return rf"^https?:\/\/{host_re}{path}"
    return rf"^https?:\/\/[^\/]+{path}"


def pick(rules, tier):
    return [r for r in rules if r["tier"] == "core" or tier == "full"]


def mitm_for(rules, tier, extra):
    hosts = [r["host"].lower() for r in pick(rules, tier) if r["host"]]
    if tier == "full":
        hosts += extra
    seen = []
    for h in hosts:
        if h and h not in seen:
            seen.append(h)
    return seen


def write_surge(tier, rules, mitm):
    lines = [f"#!name=NoAS 路径层 · {tier}",
             "#!desc=开屏/广告接口拦截（NoAS L2）。只拦广告接口，不碰正文。",
             "#!author=NoS-1", f"#!homepage={HOME}",
             "#!category=NoAS",
             f"#!reject={len(rules)}", f"#!mitm={len(mitm)}",
             f"#!total={len(rules) + len(mitm)}", "", "[URL Rewrite]"]
    lines += [f"{compile_pattern(r)} {r['action']}" for r in rules]
    lines += ["", "[MITM]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / tier / "noas-path.sgmodule").write_text("\n".join(lines), encoding="utf-8")


def write_loon(tier, rules, mitm):
    lines = [f"#!name=NoAS 路径层 · {tier}",
             "#!desc=开屏/广告接口拦截（NoAS L2）。只拦广告接口，不碰正文。",
             "#!author=NoS-1", f"#!homepage={HOME}",
             "#!system=ios,macos",
             f"#!reject={len(rules)}", f"#!mitm={len(mitm)}",
             f"#!total={len(rules) + len(mitm)}", "", "[Rewrite]"]
    lines += [f"{compile_pattern(r)} - {r['action']}" for r in rules]
    lines += ["", "[MitM]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / tier / "noas-path.plugin").write_text("\n".join(lines), encoding="utf-8")


def write_qx(tier, rules, mitm):
    lines = [f"# NoAS 路径层 · {tier}（QuantumultX）",
             f"# 源：{HOME}", "# 只拦广告接口，不碰正文", "",
             "[rewrite_local]"]
    lines += [f"{compile_pattern(r)} url {r['action']}" for r in rules]
    lines += ["", "[mitm]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / tier / "noas-path.conf").write_text("\n".join(lines), encoding="utf-8")


def write_plain(tier, rules, mitm):
    txt = ["# 路径层纯文本清单（便于自查与二次转换）",
           "# 字段：动作 <TAB> App <TAB> 用途 <TAB> 正则"]
    for r in rules:
        txt.append(f"{r['action']}\t{r['app']}\t{r['note']}\t{compile_pattern(r)}")
    (OUT / tier / "paths.txt").write_text("\n".join(txt) + "\n", encoding="utf-8")
    (OUT / tier / "mitm.txt").write_text("\n".join(mitm) + "\n", encoding="utf-8")


def main():
    rules = read_rules()
    extra = read_mitm_extra()
    OUT.mkdir(parents=True, exist_ok=True)
    manifest = {"tiers": {}}
    for tier in TIERS:
        (OUT / tier).mkdir(parents=True, exist_ok=True)
        picked = pick(rules, tier)
        mitm = mitm_for(rules, tier, extra)
        write_surge(tier, picked, mitm)
        write_loon(tier, picked, mitm)
        write_qx(tier, picked, mitm)
        write_plain(tier, picked, mitm)
        manifest["tiers"][tier] = {"rules": len(picked), "mitm": len(mitm),
                                   "actions": sorted({r["action"] for r in picked})}
    manifest["source"] = HOME + "/blob/main/lists/ad_paths.tsv"
    manifest["note"] = "L2 路径层只拦广告接口；通用路径仅 full 档，范围由 MITM 白名单限定"
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))


if __name__ == "__main__":
    main()
