#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_ad_paths.py —— 从已审计的广告端点表生成 L2 路径层规则。

为什么要有这一步：
  L1（DNS）只能按域名拦；域名被白名单父域保护、或 App 直接走 IP 时，DNS 拦不到。
  L2（MITM 路径）是唯一兜底。人工审计的 L2 规则只有 14 条，而端点表已有 64 个
  "纯广告端點"域——这些域本来就不承载业务，对它们做路径拦截不会伤到正常功能。

约束（与 build_paths.py 一致）：
  1. 只为"纯广告端点域"生成，绝不为业务主域生成 → MITM 范围不会碰到用户正常流量；
  2. core 档每条都锚定具体主机，不收空主机规则；
  3. 只用 reject-dict（广告接口多为 JSON，返回 {} 不会让 App 崩）；
  4. 不使用 `.*` 通配，路径只匹配广告语义段；
  5. 输出 lists/ad_paths_auto.tsv，可重复生成；人工审计规则仍写在 ad_paths.tsv，两者合并不冲突。
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EP = ROOT / "lists" / "ad_endpoints.txt"
OUT = ROOT / "lists" / "ad_paths_auto.tsv"

# 路径只取"广告语义"，且必须以 / 收尾，避免命中正文页面
PATH_MAIN = r"/(ads?|adverts?|advertise|advertisement|adserver|adx|splash|openads?|banner)/"
PATH_API = r"/api/(ads?|advertise|adinfo|adlist|adsense)/"

# 国内优先（这些端点直接对应国内 App 的广告请求，给第二条变体）
CN_HINTS = (
    "baidu", "qq.com", "gdt", "alimama", "toutiao", "pangolin", "umeng", "meituan",
    "kuaishou", "bilibili", "xiaomi", "huawei", "oppo", "vivo", "honor", "sina",
    "sohu", "netease", "163.com", "csdn", "zhihu", "douban", "weibo", "aliyun",
)


def cn_like(d):
    return d.endswith(".cn") or any(h in d for h in CN_HINTS)


def main():
    if not EP.exists():
        print("缺少 lists/ad_endpoints.txt", file=sys.stderr)
        return 1
    rows = []
    for line in EP.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line or line.startswith("!"):
            continue
        d = line.lstrip("|").rstrip("^").strip()
        if d and "." in d:
            rows.append(d)
    rows = sorted(set(rows))

    gen = []
    for d in rows:
        gen.append((d, PATH_MAIN, "广告端点（主路径族）"))
    for d in rows:
        if cn_like(d):
            gen.append((d, PATH_API, "国内高频端点（API 变体）"))

    lines = [
        "# 本文件由 tools/gen_ad_paths.py 自动生成，请勿手改；人工规则写在 ad_paths.tsv",
        "# 来源：lists/ad_endpoints.txt（人工审计的纯广告端点表）",
        "# host\tpath_regex\taction\tapp\tnote\ttier",
    ]
    for d, path, note in gen:
        lines.append("\t".join([d, path, "reject-dict", "广告端点", note, "core"]))
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    core_main = len(rows)
    core_api = len(gen) - core_main
    print("生成 %d 条路径规则：主路径 %d + 国内 API 变体 %d｜端点 %d 个｜输出 %s"
          % (len(gen), core_main, core_api, len(rows), OUT.relative_to(ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
