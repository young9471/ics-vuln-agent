# 一键发布到 GitHub（需先安装 gh CLI 并登录你的账号）
# 用法：
#   powershell -ExecutionPolicy Bypass -File scripts\publish-github.ps1            # 公开仓库
#   powershell -ExecutionPolicy Bypass -File scripts\publish-github.ps1 -Private   # 私有仓库
param(
  [string]$RepoName = "ics-vuln-agent",
  [switch]$Private,
  [string]$Description = "ICS VulnAgent — 工控系统脆弱性分析与利用智能体（P1-P9：协议逆向→漏洞测绘→验证与Fuzz→EXP与报告）"
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Git = Join-Path $Root "runtime\git\cmd\git.exe"
if (-not (Test-Path $Git)) { $Git = "git" }

# 1. gh CLI
$gh = Get-Command gh -ErrorAction SilentlyContinue
if (-not $gh) {
  Write-Host "[publish] 未找到 gh CLI。安装（任选其一）：" -ForegroundColor Yellow
  Write-Host "  winget install --id GitHub.cli"
  Write-Host "  或从 https://cli.github.com 下载安装"
  Write-Host "安装后重新打开终端，先执行: gh auth login"
  exit 1
}

# 2. 登录态
& gh auth status 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
  Write-Host "[publish] 尚未登录 GitHub，正在启动登录流程（浏览器授权）…" -ForegroundColor Yellow
  & gh auth login --hostname github.com --git-protocol https --web
  if ($LASTEXITCODE -ne 0) { throw "gh auth login 失败" }
}

# 3. 确认提交存在
& $Git -C $Root rev-parse --verify HEAD 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "仓库尚无提交，先 git add/commit" }

# 4. 创建远端仓库并推送
$visibility = if ($Private) { "--private" } else { "--public" }
Write-Host "[publish] 创建仓库 $RepoName ($visibility) 并推送…" -ForegroundColor Cyan
& gh repo create $RepoName $visibility --description $Description --source $Root --remote origin --push
if ($LASTEXITCODE -ne 0) { throw "gh repo create 失败（同名仓库已存在？改用: git remote add origin https://github.com/<你>/$RepoName.git; git push -u origin main）" }

Write-Host "[publish] 完成：https://github.com/$(& gh api user --jq .login)/$RepoName" -ForegroundColor Green
