#!/usr/bin/env python3
"""演示案例 26（WAGO 750-8202）V2 漏洞挖掘视图数据构造。

磁盘 findings.json 是平台正本（服务重启后 file->DB 同步以它为准），所以演示
数据直接写进 <case>/findings.json，再由 --emit-sql 生成 DB 同步 SQL。
用法:
  python demo26_build.py            # 注入 V2 sections（device_profile/vuln_surface/假设/campaign）
  python demo26_build.py --emit-sql # 读取当前 findings.json 生成 UPDATE SQL（exp_gen 之后跑）
"""
import argparse
import datetime
import json
import sys
from pathlib import Path

FINDINGS = Path(r"C:\科研\114项目\protocol-agent\platform\data\protocol_cases\case-26\findings.json")
SQL_OUT = Path(r"C:\Users\admin\AppData\Local\Temp\demo26_sync.sql")


def now(offset_min=0):
    t = datetime.datetime.now() + datetime.timedelta(minutes=offset_min)
    return t.isoformat(timespec="seconds")


def build_sections():
    profile = {
        "facts": {"vendor": "WAGO", "model": "750-8202 (PFC200)", "firmware": "FW14",
                  "os": "Linux RT", "device_ip": "192.168.1.30"},
        "firmware_obtainable": "可获取（Web 固件下载页直接下载 FW 包）",
        "tracks": ["protocol", "firmware"],
        "ports_scanned": {"80/tcp": True, "502/tcp": True, "161/udp": True,
                          "21/tcp": False, "22/tcp": False, "23/tcp": False},
        "matrix": {
            "identity_read": {"protocol": [{"ref": "frame:0x1E identify→设备名/固件", "grade": "live"}],
                              "service": [{"ref": "SNMP sysDescr=FW14", "grade": "live"}], "physical": []},
            "mem_read": {"protocol": [{"ref": "frame:0x04 read holding", "grade": "live"}],
                         "service": [], "physical": []},
            "mem_write": {"protocol": [{"ref": "frame:0x06 write single", "grade": "live"}],
                          "service": [], "physical": []},
            "run_control": {"protocol": [{"ref": "frame:0x05 coil 0x3400 停机", "grade": "live"}],
                            "service": [], "physical": []},
            "logic_download": {"protocol": [{"ref": "frame:0x71 块下载(未授权成功)", "grade": "live"}],
                               "service": [{"ref": "CODESYS web :2455", "grade": "static"}], "physical": []},
            "write_protect": {"protocol": [], "service": [], "physical": []},
            "dos_surface": {"protocol": [{"ref": "畸形长度域→疑似复位", "grade": "inferred"}],
                            "service": [{"ref": "tcp/502 半开连接", "grade": "static"}], "physical": []},
            "firmware_obtain": {"protocol": [],
                                "service": [{"ref": "http /firmware FW14", "grade": "live"}],
                                "physical": [{"ref": "SD 卡镜像导出", "grade": "static"}]},
        },
        "ts": now(),
    }

    app_items = [
        {"template_id": "V1A-anon-identity", "vclass": 1, "name": "匿名身份/固件版本泄露",
         "risk": "read", "detection": "deterministic", "state": "applicable"},
        {"template_id": "V2A-auth-not-enforced", "vclass": 2, "name": "协议认证未强制",
         "risk": "write", "detection": "deterministic", "state": "applicable"},
        {"template_id": "V3A-unauth-runstop", "vclass": 3, "name": "未授权远程启停",
         "risk": "destructive", "detection": "deterministic", "state": "applicable"},
        {"template_id": "V5A-logic-tamper", "vclass": 5, "name": "控制逻辑程序篡改",
         "risk": "write", "detection": "fuzz", "state": "applicable"},
        {"template_id": "V6A-write-protect-bypass", "vclass": 6, "name": "读写保护破解",
         "risk": "write", "detection": "fuzz", "state": "unknown", "missing_caps": ["write_protect"]},
        {"template_id": "V7A-proto-dos", "vclass": 7, "name": "协议拒绝服务",
         "risk": "destructive", "detection": "fuzz", "state": "applicable"},
        {"template_id": "V8B-ftp-anonymous", "vclass": 8, "name": "FTP 匿名访问",
         "risk": "read", "detection": "deterministic", "state": "not_applicable",
         "reason": "FTP 服务未开放（端口探测 21/tcp 关闭）"},
        {"template_id": "V9B-telnet-service", "vclass": 9, "name": "Telnet 明文管理面",
         "risk": "read", "detection": "deterministic", "state": "not_applicable",
         "reason": "Telnet 未开放（23/tcp 关闭）"},
        {"template_id": "V10A-replay-no-session", "vclass": 10, "name": "无会话绑定的请求重放",
         "risk": "write", "detection": "deterministic", "state": "applicable"},
        {"template_id": "V13A-physical-io", "vclass": 13, "name": "物理 I/O 直接操纵",
         "risk": "write", "detection": "fuzz", "state": "unknown", "missing_caps": ["physical_io"]},
    ]
    summary = {
        "total": len(app_items),
        "applicable": sum(1 for i in app_items if i["state"] == "applicable"),
        "not_applicable": sum(1 for i in app_items if i["state"] == "not_applicable"),
        "unknown": sum(1 for i in app_items if i["state"] == "unknown"),
    }
    applicability = {
        "summary": summary,
        "items": app_items,
        "posture_tasks": [
            {"capability": "write_protect", "hint": "发送 0x2A 保护状态查询帧确认是否启用",
             "blocks": ["V6A-write-protect-bypass"]},
            {"capability": "physical_io", "hint": "P7a 现场确认 DI/DO 通道映射",
             "blocks": ["V13A-physical-io"]},
        ],
    }

    intel = {
        "ts": now(-95),
        "query": {"vendor": "WAGO", "product": "750-8202", "version": "FW14", "protocol": "modbus"},
        "plc_intel": {"ok": False, "hits": [], "error": "plc-intel API 未启动 (127.0.0.1:4320)"},
        "icsvuln": {"ok": True, "hits": []},
        "kb": {"ok": True, "hits": []},
        "merged": [
            {"cve_id": "CVE-2019-18202", "vclass": 1, "vclass_guess": 1, "source": "kb",
             "summary": "Information Disclosure is possible on WAGO Series PFC100 and PFC200 devices before firmware version 14, because of unfinished HTTP requests.",
             "protocols": ["http"]},
            {"cve_id": "CVE-2018-8836", "vclass": 7, "vclass_guess": 7, "source": "kb",
             "summary": "WAGO 750 Series PLCs with firmware version 10 and prior include a remote attack vector that allows for an attacker to reboot the device."},
            {"cve_id": "CVE-2019-5159", "vclass": 8, "vclass_guess": 8, "source": "kb",
             "summary": "An exploitable improper input validation vulnerability exists in the firmware update functionality of WAGO PFC200."},
            {"cve_id": "CVE-2019-5184", "vclass": 7, "vclass_guess": 7, "source": "kb",
             "summary": "An exploitable double free vulnerability exists in the iocheckd service I/O-Check of WAGO PFC200.",
             "protocols": ["iocheckd"]},
            {"cve_id": "CVE-2021-34584", "vclass": 9, "vclass_guess": 9, "source": "kb",
             "summary": "Crafted web server requests can be utilised to read partial stack or heap memory on WAGO PFC200 devices.",
             "protocols": ["http"]},
            {"cve_id": "CVE-2023-5188", "vclass": 7, "vclass_guess": 7, "source": "kb",
             "summary": "The MMS Interpreter of WagoAppRTU in versions below 1.4.6.0 allows an attacker to send a malicious request causing the device to reset.",
             "protocols": ["mms"]},
        ],
        "sources_ok": {"plc_intel": False, "icsvuln": True, "kb": True},
    }

    hypotheses = [
        {"id": "H-V1A-anon-identity", "template_id": "V1A-anon-identity", "vclass": 1,
         "name": "匿名身份/固件版本泄露（identify 无鉴权返回设备名+固件）",
         "risk": "read", "detection": "deterministic", "state": "confirmed",
         "requires_approval": False,
         "plan": "发送 identify 帧，断言响应含设备名与固件串",
         "verdict_rule": "响应 >=16B 且含 'WAGO' 与 'FW14' 即 confirmed",
         "evidence": [{"ref": "campaign:CAMP-V1A-verify", "grade": "lab",
                       "frames": ["1e01000000065741474f"],
                       "expect": {"min_bytes": 16}}],
         "ts": now(-80)},
        {"id": "H-V2A-auth-not-enforced", "template_id": "V2A-auth-not-enforced", "vclass": 2,
         "name": "协议认证未强制（写请求无会话 token 仍被接受）",
         "risk": "write", "detection": "deterministic", "state": "pending",
         "requires_approval": True,
         "plan": "在不建立会话的情况下发送写帧，观察是否返回正常 ACK（P8 verify 待审批）",
         "evidence": [], "ts": now(-78)},
        {"id": "H-V3A-unauth-runstop", "template_id": "V3A-unauth-runstop", "vclass": 3,
         "name": "未授权远程启停（停机线圈可直接写）",
         "risk": "destructive", "detection": "deterministic", "state": "confirmed",
         "requires_approval": True,
         "plan": "实验室标记区写 0x3400 停机线圈，断言设备进入 STOP 且无认证拒绝",
         "verdict_rule": "写后 status 区出现 STOP 且响应为正常 ACK 即 confirmed",
         "evidence": [{"ref": "campaign:CAMP-V3A-verify(已批准#3)", "grade": "lab",
                       "frames": ["05003400ff00"],
                       "expect": {"min_bytes": 8}}],
         "ts": now(-60)},
        {"id": "H-V5A-logic-tamper", "template_id": "V5A-logic-tamper", "vclass": 5,
         "name": "控制逻辑程序篡改（块下载无签名校验）",
         "risk": "write", "detection": "fuzz", "state": "inconclusive",
         "requires_approval": True,
         "plan": "fuzz 0x71 块下载的长度域/块号域，观察校验失败类响应",
         "evidence": [{"ref": "campaign:CAMP-V5A-fuzz", "grade": "lab",
                       "note": "1240 包未触发块校验失败；发现保护拒绝类响应 err_2a_protect"}],
         "ts": now(-40)},
        {"id": "H-V7A-proto-dos", "template_id": "V7A-proto-dos", "vclass": 7,
         "name": "协议拒绝服务（畸形长度域疑似触发复位）",
         "risk": "destructive", "detection": "fuzz", "state": "pending",
         "requires_approval": True,
         "plan": "fuzz 长度域/功能码域，Guardian 监测 sysUpTime 复位（campaign 待审批 #4）",
         "evidence": [{"ref": "P3 观察", "grade": "inferred",
                       "note": "pcap 中一次畸形长度帧后 90s 无响应，疑似重启"}],
         "ts": now(-30)},
    ]

    campaigns = [
        {"campaign_id": "CAMP-V1A-verify", "hypothesis": "H-V1A-anon-identity",
         "mode": "verify", "risk": "read", "started": now(-82), "finished": now(-81),
         "approval": "-", "packets_sent": 2,
         "verify_verdicts": [
             {"label": "identify→设备名", "verdict": "confirmed", "expect_fail": ""},
             {"label": "identify→固件串", "verdict": "confirmed", "expect_fail": ""}],
         "result": "2/2 项确认", "_redline": False, "guardian": {"red_line": False}},
        {"campaign_id": "CAMP-V5A-fuzz", "hypothesis": "H-V5A-logic-tamper",
         "mode": "fuzz", "risk": "write", "started": now(-55), "finished": now(-52),
         "approval": "APPROVED#3", "packets_sent": 1240, "duration_sec": 182.4,
         "response_histogram": {"ok": 812, "err_0c": 57, "no_resp": 371},
         "new_classes": ["err_2a_protect"], "reconnects": 1, "crashes": [],
         "guardian": {"red_line": False}, "_redline": False,
         "result": "无崩溃；发现保护拒绝类 err_2a_protect（转 V6 写保护假设）"},
    ]

    return {"device_profile": profile,
            "vuln_surface": {"applicability": applicability, "intel_matches": intel,
                             "ts_applicability": now(-90)},
            "vuln_hypotheses": hypotheses,
            "campaigns": campaigns,
            "exploit_assets": []}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--emit-sql", action="store_true",
                    help="不注入，读 findings.json 生成 DB 同步 SQL")
    args = ap.parse_args()

    data = json.loads(FINDINGS.read_text(encoding="utf-8"))
    if args.emit_sql:
        text = FINDINGS.read_text(encoding="utf-8")
        if "$demo26$" in text:
            print("error: 内容含定界符", file=sys.stderr)
            return 1
        SQL_OUT.write_text(
            "UPDATE protocol_cases SET findings = $demo26$" + text + "$demo26$::jsonb, "
            "updated_at = now() WHERE id = 26;\n",
            encoding="utf-8")
        print(f"sql -> {SQL_OUT} ({len(text)} chars)")
        return 0

    sections = build_sections()
    data.update(sections)
    data["updated"] = now()
    FINDINGS.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"findings.json 更新: "
          f"applicability={sections['vuln_surface']['applicability']['summary']} "
          f"intel={len(sections['vuln_surface']['intel_matches']['merged'])} "
          f"hyps={len(sections['vuln_hypotheses'])} campaigns={len(sections['campaigns'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
