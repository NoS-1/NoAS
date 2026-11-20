#!/usr/bin/env python3
"""CF 令牌轮换（自助一步一步，失败即回滚，绝不留下半个状态）。

背景（实测，不是推测）：
  1. account token（cfat_ 前缀）**无法管理其它 token**——CF 返回
     `sub-token is not allowed to have permissions to manage other tokens`，
     所以拿手里的 CF_API_TOKEN 去创建/删除 token 在协议层就被拒。
  2. `/accounts/{id}/tokens` 列表里没有 expires_on，account token 长期有效，
     也没有 TTL 可读——"到期自动换"这件事在 CF 侧不存在。
  3. 真正能轮换的路径只有一条：一个 user 级 API Token（在 CF 后台以个人身份建，
     权限含 User API Tokens: Edit）作为"根"，由它去签发新的 account token。
     这个根令牌必须人工建一次（放进 creds.env 的 CF_USER_TOKEN），之后全自动。

因此本脚本的行为：
  - 没有 CF_USER_TOKEN → 退出码 0，打印一句"未自举，跳过"，不阻塞任何流程；
  - 有 CF_USER_TOKEN → 建新 token → verify → 写 GitHub secret → 回写 creds.env → 删旧 token。
    任何一步失败都删掉新 token 并保留旧值，绝不让两端对不上。

用法：
  python3 tools/cf_rotate.py [--check]   # --check 只看能不能轮换，不动手
  python3 tools/cf_rotate.py --force     # 无视轮换间隔强制换
"""
import argparse
import base64
import datetime as dt
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"
CREDS = pathlib.Path("/home/user/.noas/creds.env")
STATE = pathlib.Path(__file__).resolve().parent.parent / "state" / "cf_rotation.json"
REPO = "NoS-1/NoAS"
SECRET_NAMES = {"CF_API_TOKEN"}
ROTATE_EVERY_DAYS = 30


def load_creds() -> dict:
    out = {}
    if CREDS.exists():
        for line in CREDS.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    for k in ("CF_USER_TOKEN", "CF_API_TOKEN", "CF_ACCOUNT_ID", "GH_PAT"):
        if not out.get(k):
            out.setdefault(k, os.environ.get(k, ""))
    return out


def cf(method: str, path: str, token: str, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            return f.status, json.load(f)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {"errors": [{"message": e.read()[:200].decode("utf-8", "ignore")}]}
    except Exception as e:
        return -1, {"errors": [{"message": f"{type(e).__name__}: {e}"}]}


def gh(method: str, path: str, token: str, body=None):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        method=method,
        headers={"Authorization": f"token {token}", "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json"},
        data=json.dumps(body).encode() if body is not None else None,
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as f:
            return f.status, (json.load(f) if f.length != 0 else {})
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:
            return e.code, {}


def put_secret(pat: str, name: str, value: str) -> tuple[int, dict]:
    try:
        from nacl import encoding, public
    except ImportError:
        return -2, {"error": "pynacl 缺失"}
    s, kj = gh("GET", f"/repos/{REPO}/actions/secrets/public-key", pat)
    if s != 200:
        return s, kj
    pk = public.PublicKey(kj["key"].encode(), encoding.Base64Encoder)
    sealed = base64.b64encode(public.SealedBox(pk).encrypt(value.encode())).decode()
    return gh("PUT", f"/repos/{REPO}/actions/secrets/{name}",
              pat, {"encrypted_value": sealed, "key_id": kj["key_id"]})


def writable_policies(pol_in: list) -> tuple[list, list]:
    """去掉"管理令牌"类权限组：新令牌不该继承签发自身的能力（最小权限 + 避免自举放大）。"""
    out, dropped = [], []
    for p in pol_in:
        groups = []
        for g in p.get("permission_groups", []):
            name = (g.get("name") or "").lower()
            if "token" in name and ("api" in name or "user" in name or "account" in name):
                dropped.append(g.get("name"))
                continue
            groups.append({"id": g["id"]})
        if groups:
            out.append({"effect": "allow", "resources": p["resources"], "permission_groups": groups})
    return out, dropped


def doctor(c: dict, acc: str) -> int:
    """根令牌出事时的第一站：把四段链路逐段点亮，并直接给出下一步动作。

    设计原则：任何一段坏了，结论必须写成"去点哪里、跑哪条命令"，不留给记忆。
    """
    root, cur, pat = c.get("CF_USER_TOKEN", ""), c.get("CF_API_TOKEN", ""), c.get("GH_PAT", "")
    fixes = []

    # 1 根令牌：唯一能签令牌的东西
    if not root:
        print("✗ 根令牌：未配置 CF_USER_TOKEN")
        fixes.append("去 dash.cloudflare.com/profile/api-tokens 建一枚 NoAS-Root"
                     "（Account｜Account API Tokens｜Edit + User｜API Tokens｜Edit），写入 creds.env")
    else:
        s, d = cf("GET", "/user/tokens/verify", root)
        st = (d.get("result") or {}).get("status")
        mark = "✓" if s == 200 and st == "active" else "✗"
        print(f"{mark} 根令牌：http={s} status={st}")
        if mark == "✗":
            fixes.append("根令牌已失效/被删：回 CF 后台重建 NoAS-Root 并替换 creds.env 的 CF_USER_TOKEN，"
                         "然后跑 python3 tools/cf_rotate.py --force")

    # 2 现用账号令牌：真正部署 Pages/Worker/D1 的那枚
    if not cur:
        print("✗ 现用令牌：未配置 CF_API_TOKEN")
        fixes.append("creds.env 补 CF_API_TOKEN，最快路径是根令牌就绪后跑 --force 直接签一枚新的")
    else:
        s, d = cf("GET", f"/accounts/{acc}/tokens/verify", cur)
        st = (d.get("result") or {}).get("status")
        mark = "✓" if s == 200 and st == "active" else "✗"
        print(f"{mark} 现用令牌：http={s} status={st}")
        if mark == "✗":
            fixes.append("现用令牌失效：python3 tools/cf_rotate.py --force 会用根令牌签新的并回写 secret")

    # 3 GitHub secret：CI 读的就是它
    if not pat:
        print("✗ GitHub：无 GH_PAT，无法核对 secret")
    else:
        s, d = gh("GET", f"/repos/{REPO}/actions/secrets", pat)
        names = [x["name"] for x in d.get("secrets", [])] if s == 200 else []
        print(f"{'✓' if 'CF_API_TOKEN' in names else '✗'} GitHub secret CF_API_TOKEN："
              f"http={s} {'已存在' if 'CF_API_TOKEN' in names else '不存在'}")
        if s != 200:
            fixes.append(f"GH_PAT 读不到仓库 secret（http={s}）：PAT 需有 secrets 读权限")
        elif "CF_API_TOKEN" not in names:
            fixes.append("仓库缺 CF_API_TOKEN secret：轮换脚本 --force 会自动写入")

         # 4 与本地的一致性：secret 更新时间和本地轮换时间应当接近
    if STATE.exists():
        try:
            st_ = json.loads(STATE.read_text(encoding="utf-8"))
            print(f"· 上次轮换：{st_.get('last_rotated')}  新 id={st_.get('new_id')} 旧 id={st_.get('old_id')}")
            last = dt.datetime.fromisoformat(st_["last_rotated"].replace("Z", "+00:00"))
            age = (dt.datetime.now(dt.timezone.utc) - last).days
            print(f"· {age} 天前，阈值 {ROTATE_EVERY_DAYS} 天" + ("，该轮换了" if age >= ROTATE_EVERY_DAYS else ""))
        except Exception as e:
            print(f"· 轮换台账读不出来：{type(e).__name__}")
    else:
        print("· 无轮换台账 state/cf_rotation.json（还没轮换过）")

    print()
    if fixes:
        print("下一步：")
        for i, f in enumerate(fixes, 1):
            print(f"  {i}. {f}")
        return 1
    print("结论：四段链路齐全，无需处理")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="只体检不轮换")
    ap.add_argument("--doctor", action="store_true", help="根令牌故障诊断：逐段点亮并给出下一步")
    ap.add_argument("--force", action="store_true", help="忽略间隔强制轮换")
    ap.add_argument("--keep-old", action="store_true", help="保留旧令牌不删除")
    a = ap.parse_args()

    c = load_creds()
    acc = c.get("CF_ACCOUNT_ID", "") or "226431c8f431ebb75d82dd5dbd5e8d86"
    cur = c.get("CF_API_TOKEN", "")
    root, pat = c.get("CF_USER_TOKEN", ""), c.get("GH_PAT", "")
    if a.doctor:
        return doctor(c, acc)
    if not cur:
        print("· 无 CF_API_TOKEN（CI 未配置 / 本地没凭据），跳过轮换")
        return 0

    # 现状体检
    s, d = cf("GET", f"/accounts/{acc}/tokens/verify", cur)
    print(f"· 现令牌 verify：http={s} status={(d.get('result') or {}).get('status')}")
    s, d = cf("GET", f"/accounts/{acc}/tokens", cur)
    cur_id = None
    if s == 200:
        for t in d["result"]:
            if t.get("status") == "active":
                cur_id = t["id"]
                print(f"· 现令牌 id={cur_id} 建于 {t.get('issued_on')} 末次使用 {t.get('last_used_on')}")
                break
    if not root:
        print("· 未配置 CF_USER_TOKEN（user 级根令牌），CF 侧无法自助轮换 —— 跳过，不影响构建")
        print("  一次性自举：CF 后台 → 我的资料 → API 令牌 → 建「User API Tokens: Edit」，"
              "写入 creds.env 的 CF_USER_TOKEN 即永久生效")
        return 0

    state = {}
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    if not a.force and state.get("last_rotated"):
        last = dt.datetime.fromisoformat(state["last_rotated"].replace("Z", "+00:00"))
        age = (dt.datetime.now(dt.timezone.utc) - last).days
        print(f"· 上次轮换 {state['last_rotated']}（{age} 天前，阈值 {ROTATE_EVERY_DAYS} 天）")
        if age < ROTATE_EVERY_DAYS and not a.check:
            print("· 未到期，跳过（--force 可强制）")
            return 0

    # 用根令牌取策略，生成最小权限策略
    s, d = cf("GET", f"/accounts/{acc}/tokens", root)
    if s != 200:
        print(f"✗ 根令牌读不到令牌列表：http={s} {d.get('errors')}")
        return 1
    base = next((t for t in d["result"] if t["id"] == cur_id), d["result"][0])
    pols, dropped = writable_policies(base["policies"])
    print(f"· 策略：{len(pols)} 组，剔除管理令牌权限 {len(dropped)} 个{dropped[:2]}")

    if a.check:
        print("✓ 根令牌可用，轮换链路具备（--check 不动手）")
        return 0

    s, d = cf("POST", f"/accounts/{acc}/tokens", root,
              {"name": f"noas-rotated-{dt.datetime.now(dt.timezone.utc):%Y%m%d%H%M}", "policies": pols})
    if s != 200 or not d.get("success"):
        print(f"✗ 创建新令牌失败：http={s} {d.get('errors')}")
        return 1
    new = d["result"]
    new_tok, new_id = new.get("value", ""), new["id"]
    print(f"✓ 新令牌已签发 id={new_id} 长度 {len(new_tok)}")

    ok = True
    s, d = cf("GET", f"/accounts/{acc}/tokens/verify", new_tok)
    if s != 200 or (d.get("result") or {}).get("status") != "active":
        print(f"✗ 新令牌 verify 未通过：http={s} {d}")
        ok = False
    if ok and not pat:
        print("✗ 无 GH_PAT，无法自动写 secret")
        ok = False
    if ok:
        s, d = put_secret(pat, "CF_API_TOKEN", new_tok)
        if s not in (201, 204):
            print(f"✗ 写 GitHub secret 失败：http={s} {d}")
            ok = False
        else:
            print("✓ GitHub secret CF_API_TOKEN 已更新")

    if not ok:
        s, _ = cf("DELETE", f"/accounts/{acc}/tokens/{new_id}", root)
        print(f"↩ 回滚：新令牌已删除 http={s}；旧令牌 {cur_id} 未动")
        return 1

    # 回写 creds.env（原子替换，保 600）
    lines = CREDS.read_text(encoding="utf-8").splitlines()
    kept = [l for l in lines if not l.startswith("CF_API_TOKEN=")]
    kept.append(f"CF_API_TOKEN={new_tok}")
    tmp = CREDS.with_suffix(".tmp")
    tmp.write_text("\n".join(kept) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(CREDS)
    print("✓ creds.env 已更新（600）")

    if not a.keep_old and cur_id:
        s, d = cf("DELETE", f"/accounts/{acc}/tokens/{cur_id}", root)
        print(f"· 旧令牌删除：http={s} success={d.get('success')}")

    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps({
        "last_rotated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "new_id": new_id, "old_id": cur_id, "dropped_groups": dropped,
        "policies": len(pols),
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    print("✓ 轮换完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
