#!/usr/bin/env python3
"""build_mixed.py —— 把 L1(DNS) + L2(路径) + L3(内容) 合并成"一份订阅"产物。

为什么需要合并包：
  支持 MITM 的客户端（Surge/Loon/QuantumultX）本来要分别导入三套东西，
  容易漏配。这里把 DNS 域名拦截与路径改写写进同一个模块，
  L3 内容层（uBO）无法进入这类客户端，只在 manifest 里给出链接。

设计约束：
  1. 合并包里的 DNS 部分只用 lite 档（≤1 万条），避免模块过大拖慢客户端启动；
  2. 路径部分只带 core 档（每条锚定具体主机），full 档仍走单独的 paths 订阅；
  3. 不发明新语法，三端都用各自原生段落，导入即可用。
"""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SUBS = ROOT / "subs"
OUT = SUBS / "mixed"
HOME = "https://github.com/NoS-1/NoAS"
PAGES = "https://nos-1.github.io/NoAS"


def read_domains(path):
    out = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip()
        if line and "." in line and "/" not in line:
            out.append(line.lower())
    return out


def read_core_paths():
    rules = []
    tsv = ROOT / "lists" / "ad_paths.tsv"
    if not tsv.exists():
        return rules
    for line in tsv.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) != 6 or parts[5].strip() != "core":
            continue
        host, path, action = parts[0].strip().lower(), parts[1].strip(), parts[2].strip()
        if not path.startswith("/") or ".*" in path:
            continue
        rules.append({"host": host, "path": path, "action": action,
                      "app": parts[3].strip(), "note": parts[4].strip()})
    return rules


def pattern(rule):
    host, path = rule["host"], rule["path"]
    if host:
        return r"^https?:\/\/%s%s" % (host.replace(".", r"\."), path)
    return r"^https?:\/\/[^\/]+" + path


def main():
    doms = sorted(set(read_domains(SUBS / "lite" / "domains.txt")))
    wild = sorted({l.strip()[2:].lower()
                   for l in (SUBS / "lite" / "wildcards.txt").read_text(encoding="utf-8").splitlines()
                   if l.strip().startswith("*.")}) if (SUBS / "lite" / "wildcards.txt").exists() else []
    rules = read_core_paths()
    mitm = []
    for r in rules:
        if r["host"] and r["host"] not in mitm:
            mitm.append(r["host"])
    OUT.mkdir(parents=True, exist_ok=True)

    # Surge：规则段 + 路径改写 + MITM
    lines = ["#!name=NoAS 合并包（L1+L2）",
             "#!desc=域名拦截(L1) + 广告接口改写(L2)，一份导入即生效",
             "#!author=NoS-1", "#!homepage=%s" % HOME, "#!category=NoAS",
             "#!dns=%d" % (len(doms) + len(wild)), "#!path=%d" % len(rules),
             "#!mitm=%d" % len(mitm), "", "[Rule]"]
    lines += ["DOMAIN-SUFFIX,%s,REJECT" % d for d in doms]
    lines += ["DOMAIN-SUFFIX,%s,REJECT" % w for w in wild]
    lines += ["", "[URL Rewrite]"]
    lines += ["%s _ %s" % (pattern(r), r["action"]) for r in rules]
    lines += ["", "[MITM]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / "noas-all.sgmodule").write_text("\n".join(lines), encoding="utf-8")

    # Loon
    lines = ["#!name=NoAS 合并包（L1+L2）",
             "#!desc=域名拦截(L1) + 广告接口改写(L2)，一份导入即生效",
             "#!author=NoS-1", "#!homepage=%s" % HOME, "#!system=ios,macos",
             "#!dns=%d" % (len(doms) + len(wild)), "#!path=%d" % len(rules),
             "#!mitm=%d" % len(mitm), "", "[Rule]"]
    lines += ["DOMAIN-SUFFIX,%s,REJECT" % d for d in doms]
    lines += ["DOMAIN-SUFFIX,%s,REJECT" % w for w in wild]
    lines += ["", "[Rewrite]"]
    lines += ["%s - %s" % (pattern(r), r["action"]) for r in rules]
    lines += ["", "[MitM]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / "noas-all.plugin").write_text("\n".join(lines), encoding="utf-8")

    # QuantumultX
    lines = ["# NoAS 合并包（L1+L2）（QuantumultX）", "# 源：%s" % HOME, "",
             "[filter_local]"]
    lines += ["host-suffix, %s, reject" % d for d in doms]
    lines += ["host-suffix, %s, reject" % w for w in wild]
    lines += ["", "[rewrite_local]"]
    lines += ["%s url %s" % (pattern(r), r["action"]) for r in rules]
    lines += ["", "[mitm]", "hostname = %APPEND% " + ",".join(mitm), ""]
    (OUT / "noas-all.conf").write_text("\n".join(lines), encoding="utf-8")

    manifest = {
        "layers": {
            "L1_dns": {"domains": len(doms), "wildcards": len(wild),
                       "source": "%s/subs/lite/" % PAGES},
            "L2_path": {"rules": len(rules), "mitm_hosts": len(mitm),
                        "source": "%s/subs/paths/core/" % PAGES},
            "L3_content": {"note": "uBO 只进浏览器，不能并入 MITM 客户端",
                           "source": "%s/subs/paths/ubo/noas-ubo.txt" % PAGES},
        },
        "files": ["noas-all.sgmodule", "noas-all.plugin", "noas-all.conf"],
        "note": "合并包只含 lite 档 DNS + core 档路径；要更激进请另装 mid/full 与 paths full",
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8")
    print("合并包：DNS %d（含通配 %d）／路径 %d 条／MITM %d 台 → %s"
          % (len(doms), len(wild), len(rules), len(mitm), OUT))


if __name__ == "__main__":
    main()
