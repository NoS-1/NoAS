#!/usr/bin/env python3
"""把本地构建出的 doh/worker.js 部署到 Cloudflare Workers（幂等）。

为什么需要它：每日构建只负责“生成 worker.js”，如果没人把它推上去，
线上 DoH 就会一直停在旧规则版本——规则天天更新、线上服务却用上个月的表，
这是最难发现的一类静默失效。这个脚本就是补上那一步，并在部署后回读比对 sha。

环境变量：CF_API_TOKEN（必需）；CF_ACCOUNT_ID 可选。
"""
import hashlib, json, os, sys, time, urllib.request, urllib.error, uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOK = os.environ.get("CF_API_TOKEN", "").strip()
ACC = os.environ.get("CF_ACCOUNT_ID", "226431c8f431ebb75d82dd5dbd5e8d86").strip()
NAME = os.environ.get("DOH_SCRIPT", "noas-doh").strip()
COMPAT = "2025-09-01"
# Analytics Engine 数据集：绑上即自动建表（CF 官方行为），首次写点后可在 SQL API 里 SHOW TABLES 看到。
# DOH_AE_DATASET=off 可临时关掉绑定（应急时一行环境变量即可退回到“纯解析、零日志”）。
AE_DATASET = os.environ.get("DOH_AE_DATASET", "noas_dns").strip()

BASE = "https://api.cloudflare.com/client/v4/accounts/%s/workers/scripts/%s" % (ACC, NAME)


def _req(url, data=None, method="GET", ctype=None):
    h = {"Authorization": "Bearer " + TOK}
    if ctype:
        h["Content-Type"] = ctype
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        return json.loads(urllib.request.urlopen(r, timeout=90).read()), None
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode("utf-8", "ignore")), "HTTP %d" % e.code
        except Exception:
            return {}, "HTTP %d" % e.code
    except Exception as e:
        return {}, str(e)


def main():
    if not TOK:
        print("DoH 部署跳过：未配置 CF_API_TOKEN")
        return 0
    path = os.path.join(ROOT, "doh", "worker.js")
    body = open(path, "rb").read()
    local = hashlib.sha256(body).hexdigest()
    print("本地 worker.js %d 字节 sha=%s" % (len(body), local[:16]))

    boundary = "----noasDoh" + uuid.uuid4().hex
    meta_obj = {"main_module": "worker.mjs", "compatibility_date": COMPAT}
    # Workers Logs 免费额度 20 万事件/天；按 1% 采样，10 万请求/天也只留约 1 千条，不抢额度。
    meta_obj["observability"] = {
        "enabled": True,
        "head_sampling_rate": 0.01,
        "logs": {"enabled": True, "head_sampling_rate": 0.01, "invocation_logs": False},
    }
    # 绑定清单：AE（观测）+ RULES（热规则 KV，CF 自更新用）
    # DOH_KV_NS=off 可关闭；命名空间不存在时部署仍能成功（Worker 会自动退回内嵌规则）
    KV_NS = os.environ.get("DOH_KV_NS", "1e20a4a1c8de4dc892e40ab2ec176f7e").strip()
    binds = []
    if AE_DATASET and AE_DATASET.lower() != "off":
        binds.append({"type": "analytics_engine", "name": "AE", "dataset": AE_DATASET})
        print("绑定 Analytics Engine：AE → %s" % AE_DATASET)
    else:
        print("Analytics Engine 绑定已关闭（DOH_AE_DATASET=off）")
    if KV_NS and KV_NS.lower() != "off":
        binds.append({"type": "kv_namespace", "name": "RULES", "namespace_id": KV_NS})
        print("绑定 KV 热规则：RULES → %s" % KV_NS)
    # 原生 Rate Limiting binding（Free 计划可用、不计额外费用）：period 只能是 10 或 60。
    # DOH_RATELIMIT=off 可关闭；关闭后 Worker 自动退回本地内存计数。
    RL = os.environ.get("DOH_RATELIMIT", "300").strip()
    if RL.lower() != "off":
        binds.append({"type": "ratelimit", "name": "LIMITER",
                      "namespace_id": "3001",
                      "simple": {"limit": int(RL), "period": 60}})
        print("绑定 Rate Limiting：LIMITER → %s 次/60s" % RL)
    if binds:
        meta_obj["bindings"] = binds
    meta = json.dumps(meta_obj).encode()
    chunks = [
        ("--" + boundary + "\r\n").encode(),
        b'Content-Disposition: form-data; name="metadata"\r\nContent-Type: application/json\r\n\r\n',
        meta, b"\r\n",
        ("--" + boundary + "\r\n").encode(),
        b'Content-Disposition: form-data; name="worker.mjs"; filename="worker.mjs"\r\nContent-Type: application/javascript+module\r\n\r\n',
        body, b"\r\n",
        ("--" + boundary + "--\r\n").encode(),
    ]
    payload = b"".join(chunks)
    res, err = _req(BASE, data=payload, method="PUT", ctype="multipart/form-data; boundary=" + boundary)
    if not res.get("success"):
        print("部署失败：%s %s" % (err, json.dumps(res.get("errors"), ensure_ascii=False)[:300]))
        return 1
    print("部署成功，回读比对…")

    # 回读：GET 返回 multipart，取出 worker.mjs 正文比对 sha，确认线上真的换成新版。
    # 刚部署完边缘可能有短暂 404/429 或一次旧副本，重取 3 次；校验失败不红构建（部署本身已成功）。
    key = b'name="worker.mjs"\r\n\r\n'

    def read_online():
        try:
            req = urllib.request.Request(BASE, headers={"Authorization": "Bearer " + TOK})
            raw = urllib.request.urlopen(req, timeout=90).read()
        except urllib.error.HTTPError as e:
            print("回读 HTTP %s" % e.code)
            return None
        except Exception as e:
            print("回读异常：%s" % e)
            return None
        i = raw.find(key)
        if i == -1:
            print("回读：未找到 worker.mjs 段")
            return None
        seg = raw[i + len(key):]
        j = seg.rfind(b"\r\n--")
        if j != -1:
            seg = seg[:j]
        return hashlib.sha256(seg).hexdigest()

    online = None
    for attempt in range(3):
        online = read_online()
        if online == local:
            print("回读一致 sha=%s，线上已是新版" % online[:16])
            return 0
        if attempt < 2:
            time.sleep(2)
    print("回读不一致/未完成：线上 %s ≠ 本地 %s（部署已成功，仅校验未完成）"
          % ((online or "unknown")[:16], local[:16]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
