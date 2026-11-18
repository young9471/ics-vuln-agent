import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ICS VulnAgent",
  version: packageJson.version,
  copyright: `© ${currentYear}, ICS VulnAgent.`,
  meta: {
    title: "ICS VulnAgent — 工控系统脆弱性分析与利用智能体",
    description: "工控系统脆弱性分析与利用智能体：私有协议逆向（P1-P6）→ 漏洞面测绘（P7）→ 验证与 Fuzz（P8）→ EXP 与报告（P9），证据分级 + 审批硬闸 + 设备监护",
  },
};
