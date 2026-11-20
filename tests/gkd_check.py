#!/usr/bin/env python3
"""GKD 订阅（L4）产物体检：外壳字段完整、应用/规则结构合法、动作白名单合规。"""
import json5
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "subs" / "gkd"
MAIN = OUT / "noas-gkd.json5"
VERSION = OUT / "noas-gkd.version.json5"

# GKD 规则允许的动作；默认动作（点击）无需显式声明
ALLOWED_ACTIONS = {"click", "clickCenter", "clickNode", "longClick", "back", "input", "custom"}

fails = []


def check(cond, msg):
    if not cond:
        fails.append(msg)


def iter_rules(group):
    rs = group.get("rules", [])
    if isinstance(rs, list):
        return rs
    return [rs] if rs else []


def main():
    check(MAIN.exists(), "缺少 GKD 主订阅文件 noas-gkd.json5")
    check(VERSION.exists(), "缺少 GKD 版本探测文件 noas-gkd.version.json5")
    if fails:
        print("FAIL：" + "；".join(fails))
        return 1

    text = MAIN.read_text(encoding="utf-8")
    data = json5.loads(text)

    # 外壳字段
    check(isinstance(data.get("id"), int) and data["id"] > 0, "订阅 id 必须是正整数")
    check(isinstance(data.get("version"), int) and data["version"] >= 0, "version 必须是非负整数")
    for field in ("name", "author", "updateUrl", "checkUpdateUrl", "supportUri"):
        check(bool(data.get(field)), "外壳缺少字段：%s" % field)
    check("MIT" in text, "未保留 MIT 来源署名")
    check("gkd-kit/subscription" in text, "未标注规则上游仓库")

    apps = data.get("apps", [])
    check(len(apps) >= 100, "覆盖应用过少：%d" % len(apps))

    seen = set()
    group_count = 0
    rule_count = 0
    for app in apps:
        app_id = app.get("id")
        app_name = app.get("name")
        check(bool(app_id), "存在缺少 appId 的应用规则")
        check(bool(app_name), "存在缺少名称的应用：%s" % app_id)
        if app_id in seen:
            fails.append("appId 重复：%s" % app_id)
        seen.add(app_id)

        for group in app.get("groups", []) or []:
            group_count += 1
            check("key" in group, "应用 %s 存在缺少 group key 的规则组" % app_id)
            check(bool(group.get("name")), "应用 %s 存在缺少名称的规则组" % app_id)
            for rule in iter_rules(group):
                rule_count += 1
                if isinstance(rule, str):
                    check(bool(rule.strip()), "应用 %s 规则选择器为空" % app_id)
                    continue
                check(isinstance(rule, dict), "应用 %s 规则类型非法：%r" % (app_id, type(rule).__name__))
                if isinstance(rule, dict):
                    check(bool(rule.get("matches")), "应用 %s 规则缺少 matches" % app_id)
                    act = rule.get("action")
                    if act is not None:
                        check(act in ALLOWED_ACTIONS, "应用 %s 出现未授权动作：%s" % (app_id, act))

    # 版本探测包必须与主订阅一致
    vpkt = json5.loads(VERSION.read_text(encoding="utf-8"))
    check(vpkt.get("id") == data["id"], "version 包 id 与主订阅不一致")
    check(vpkt.get("version") == data["version"], "version 包版本与主订阅不一致")

    if fails:
        print("FAIL GKD 体检 %d 项：" % len(fails))
        for f in fails:
            print("  · " + f)
        return 1

    print("PASS GKD 体检：%d 应用 / %d 规则组 / %d 规则（v%d）" % (
        len(apps), group_count, rule_count, data["version"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
