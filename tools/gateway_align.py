#!/usr/bin/env python3
"""Gateway 列表对齐检查（默认只读，绝不改线上）。

Gateway 是免费 50 seats 的 DoH 主通道，规则列表一旦不同步：
- 本地已剔除的域仍被 Gateway 拦 → 误拦残留；
- 本地新增的域没进 Gateway → 漏拦。
本脚本只比对并报告数字，输出不含任何域名，方便贴到公开 Issue。
"""
import json
import os
import pathlib
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
TOK = os.environ.get("CF_API_TOKEN", "").strip()


def get(path):
    # 读 62 个分片的条目时单次请求可能拖到几十秒，原来 30s 超时会偶发整步失败。
    # 45s + 3 次重试：抖动不该让"对齐校验"这个 required 步骤误红。
    last = None
    for i in range(3):
        r = urllib.request.Request(
            "https://api.cloudflare.com/client/v4/accounts/%s%s" % (ACC, path),
            headers={"Authorization": "Bearer " + TOK})
        try:
            return json.load(urllib.request.urlopen(r, timeout=45))
        except Exception as e:
            last = e
            if i < 2:
                time.sleep(2 + i * 3)
    raise last


def read_list(path):
    out = set()
    p = ROOT / path
    if not p.exists():
        return out
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.split("#", 1)[0].strip().lower()
        if not line or line.startswith("!"):
            continue
        if line.startswith("||"):
            line = line[2:].rstrip("^")
        if line.startswith("0.0.0.0 "):
            line = line.split()[-1]
        if "." in line and "/" not in line:
            out.add(line)
    return out


def root_of(d):
    parts = d.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 else d


def gateway_items(lists, prefixes):
    """并发拉取各分片条目：10 片串行要 10s+，API 本来允许 600 次/分。"""
    if isinstance(prefixes, str):
        prefixes = (prefixes,)
    targets = [x for x in lists if x["name"].startswith(tuple(prefixes))]
    items = set()
    if not targets:
        return items
    import concurrent.futures
    paths = ["/gateway/lists/%s/items?limit=2000" % x["id"] for x in targets]
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(paths))) as ex:
        for d in ex.map(get, paths):
            for i in (d.get("result") or []):
                v = (i.get("value") or "").strip().lower()
                if v:
                    items.add(v)
    return items


def report(label, gw, local, cmp_root=False):
    if cmp_root:
        gw_cmp = {root_of(x) for x in gw}
        local_cmp = {root_of(x) for x in local}
    else:
        gw_cmp, local_cmp = gw, local
    missing = len(local_cmp - gw_cmp)
    extra = len(gw_cmp - local_cmp)
    hit = len(local_cmp & gw_cmp)
    print("%s：Gateway %d ／ 本地 %d ／ 命中 %d ／ 缺 %d ／ 多余 %d%s"
          % (label, len(gw_cmp), len(local_cmp), hit, missing, extra,
             "（按根域比对）" if cmp_root else ""))
    return missing, extra


def main():
    if not TOK:
        print("Gateway 对齐检查跳过：未配置 CF_API_TOKEN")
        return 0
    lists = get("/gateway/lists").get("result") or []
    lite = read_list("subs/lite/domains.txt")
    mid = read_list("subs/mid/domains.txt")
    full = read_list("subs/full/domains.txt")
    print("Gateway 列表数：%d" % len(lists))
    t1 = gateway_items(lists, ("noas_t1_", "noas_l1_"))
    t2 = gateway_items(lists, "noas_l2_") or gateway_items(lists, "noas_t2_")
    t3 = gateway_items(lists, "noas_l3_") or gateway_items(lists, "noas_t3_")
    m1, e1 = report("小档 t1 ↔ lite", t1, lite)
    m2, e2 = report("中档 t2 ↔ mid", t2, mid, cmp_root=True)
    # Gateway 不再铺 full（列表上限 100，mid 4 万已占 40 片）：没有 l3 列表时跳过这一档
    if t3:
        m3, e3 = report("大档 t3 ↔ full", t3, full, cmp_root=True)
    else:
        m3, e3 = 0, 0
        print("大档 t3：Gateway 未铺 full（设计如此，full 只走 DoH）")
    status = "ok" if (m1 == 0 and e1 == 0) else "drift"
    print("结论：%s（小档不一致会直接影响误拦，需重建小档分片）" % status)
    out = {"t1": {"missing": m1, "extra": e1},
           "t2": {"missing": m2, "extra": e2},
           "t3": {"missing": m3, "extra": e3}, "status": status}
    (ROOT / "state" / "gateway_align.json").write_text(
        json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
