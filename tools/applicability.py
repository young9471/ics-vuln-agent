#!/usr/bin/env python3
"""P7 三态适用性评估器 + 假设种子生成。

输入：含 device_profile 节的 findings.json（先跑 device_profile.py）。
输出（写入 findings）：
  vuln_surface.applicability  每个子模板的 applicable/not_applicable/unknown
                              + not_applicable 的证据 + unknown 的探测任务
  vuln_hypotheses             applicable 的确定性/模糊模板实例化为 pending 假设

门 G 判定（gate 侧同样逻辑）：全子模板落态、unknown=0、每类至少一个结论。
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import findings as F                     # noqa: E402
import vuln_templates as VT              # noqa: E402

CAP_PROBE_HINTS = {
    "shell": "服务凭据/命令注入路径探测（V9 系列命中后由 EXP 获取；或人工提供凭据）",
    "firmware_binary": "厂商官网固件下载 / SD 导出 / 更新包解包（固件轨直接获取入口）",
    "firmware_update": "协议内更新命令或 Web 上传面探测",
    "snmp_service": "UDP 161 SNMP 探测（device_profile --snmp-probe）",
    "discovery": "UDP 广播发现探测（harness 需 UDP 能力，M2 批次）",
    "protection": "保护状态查询（V6A，需 harness 保护原语）",
    "force_table": "工程软件功能影子确认 + 协议 force 命令探测",
    "time_sync": "协议内时钟写 / SNTP 面探测",
    "session_mgmt": "会话建立序列观察（session_model 输出）",
    "auth": "登录帧存在性（P2 流量 + field_map 分类）",
    "program_transfer": "上/下载命令存在性（function_codes 语义确认）",
    "run_stop": "启停命令存在性（function_codes 语义确认）",
}


def now():
    return datetime.datetime.now().isoformat(timespec="seconds")


def evaluate(profile):
    matrix = profile.get("matrix", {})
    items, tasks, hypotheses = [], [], []
    for t in VT.TEMPLATES:
        state = VT.classify(t, matrix)
        missing = sorted(VT.missing_caps(t.get("requires"), matrix)) if state == "unknown" else []
        item = {
            "template_id": t["id"], "vclass": t["vclass"], "vclass_name": t["vclass_name"],
            "name": t["name"], "risk": t["risk"], "detection": t["detection"],
            "state": state, "cwe": t.get("cwe", []),
        }
        if state == "not_applicable":
            item["reason"] = "前置能力已探测不存在（见 device_profile 矩阵）"
        if state == "unknown":
            item["missing_caps"] = missing
            for cap in missing:
                tasks.append({
                    "capability": cap,
                    "hint": CAP_PROBE_HINTS.get(cap, "P7a 主动探测补全画像"),
                    "blocks": [t["id"]],
                })
        items.append(item)
        if state == "applicable":
            hypotheses.append({
                "id": f"H-{t['id']}",
                "template_id": t["id"], "vclass": t["vclass"],
                "name": t["name"], "risk": t["risk"], "detection": t["detection"],
                "state": "pending",
                "requires_approval": t["risk"] == "destructive",
                "plan": t.get("plan", ""),
                "verdict_rule": t.get("verdict", ""),
                "evidence": [],
                "ts": now(),
            })
    # absence-is-finding：V11A 等模板 applicable 即视为待确认假设（plan 内含判定）
    summary = {
        "total": len(items),
        "applicable": sum(1 for i in items if i["state"] == "applicable"),
        "not_applicable": sum(1 for i in items if i["state"] == "not_applicable"),
        "unknown": sum(1 for i in items if i["state"] == "unknown"),
        "by_class": {},
    }
    for i in items:
        c = str(i["vclass"])
        summary["by_class"][c] = summary["by_class"].get(c, 0) + (1 if i["state"] == "applicable" else 0)
    dedup_tasks = {}
    for task in tasks:
        key = task["capability"]
        if key in dedup_tasks:
            dedup_tasks[key]["blocks"] = sorted(set(dedup_tasks[key]["blocks"] + task["blocks"]))
        else:
            dedup_tasks[key] = task
    return {"summary": summary, "items": items,
            "posture_tasks": list(dedup_tasks.values())}, hypotheses


def main():
    ap = argparse.ArgumentParser(description="三态适用性评估（P7）")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--json", action="store_true", help="仅打印，不写回 findings")
    args = ap.parse_args()
    data = F.load(args.findings)
    profile = data.get("device_profile")
    if not profile or not profile.get("matrix"):
        print("error: findings 缺少 device_profile（先运行 device_profile.py）",
              file=sys.stderr)
        return 1
    result, hypotheses = evaluate(profile)
    if not args.json:
        surface = data.get("vuln_surface") or {}
        surface["applicability"] = result
        surface["ts_applicability"] = now()
        data["vuln_surface"] = surface
        existing = {h["id"] for h in data.get("vuln_hypotheses", [])}
        for h in hypotheses:
            if h["id"] not in existing:
                data.setdefault("vuln_hypotheses", []).append(h)
        F.save(args.findings, data)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
