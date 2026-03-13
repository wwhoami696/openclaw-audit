#!/usr/bin/env python3
"""
OpenClaw Security Audit Tool
自动检查 OpenClaw 安装的安全漏洞并给出修复建议
https://openclaw.ai | 仅用于检查自己的系统
"""

import os
import sys
import re
import json
import stat
import shutil
import socket
import subprocess
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ──────────────────────────────────────────────────────
# 颜色 & 输出
# ──────────────────────────────────────────────────────
NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def c(text, code):
    return text if NO_COLOR else f"\033[{code}m{text}\033[0m"

RED    = lambda t: c(t, "31")
ORANGE = lambda t: c(t, "33")
YELLOW = lambda t: c(t, "93")
BLUE   = lambda t: c(t, "34")
GREEN  = lambda t: c(t, "32")
CYAN   = lambda t: c(t, "36")
BOLD   = lambda t: c(t, "1")
DIM    = lambda t: c(t, "2")
WHITE  = lambda t: c(t, "97")

SEV_COLOR = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      BLUE,
    "INFO":     CYAN,
    "PASS":     GREEN,
}

def sev_label(sev: str) -> str:
    fn = SEV_COLOR.get(sev, WHITE)
    return fn(f"[{sev:8s}]")


# ──────────────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────────────
@dataclass
class Finding:
    sev: str          # CRITICAL / HIGH / MEDIUM / LOW / PASS
    title: str
    detail: str
    fix: str
    category: str = ""

@dataclass
class CheckResult:
    findings: List[Finding] = field(default_factory=list)


# ──────────────────────────────────────────────────────
# 工具函数
# ──────────────────────────────────────────────────────
def run(cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
    """运行 shell 命令，返回 (returncode, stdout, stderr)"""
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, errors="replace"
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)

def file_perm_octal(path: Path) -> Optional[int]:
    try:
        return stat.S_IMODE(path.stat().st_mode)
    except Exception:
        return None

def is_world_readable(path: Path) -> bool:
    p = file_perm_octal(path)
    return p is not None and bool(p & 0o044)

def is_group_readable(path: Path) -> bool:
    p = file_perm_octal(path)
    return p is not None and bool(p & 0o040)

def find_openclaw_dirs() -> List[Path]:
    candidates = [
        Path.home() / ".openclaw",
        Path.home() / ".claw",
        Path.home() / "openclaw",
        Path("/usr/local/lib/node_modules/openclaw"),
    ]
    # npm global root
    rc, npm_root, _ = run("npm root -g")
    if rc == 0 and npm_root:
        candidates.append(Path(npm_root) / "openclaw")
    # pnpm global
    rc2, pnpm_root, _ = run("pnpm root -g")
    if rc2 == 0 and pnpm_root:
        candidates.append(Path(pnpm_root) / "openclaw")

    return [p for p in candidates if p.exists()]

IS_MAC   = platform.system() == "Darwin"
IS_WIN   = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


# ══════════════════════════════════════════════════════
# 检查模块
# ══════════════════════════════════════════════════════

# ── 1. 配置安全 ───────────────────────────────────────
def check_running_as_root(cr: CheckResult):
    if IS_WIN:
        return
    rc, out, _ = run("ps aux")
    own_pid = str(os.getpid())
    lines = [l for l in out.splitlines()
             if re.search(r'openclaw|claw', l, re.I)
             and 'grep' not in l
             and 'audit' not in l
             and own_pid not in l]
    root_procs = [l for l in lines if l.split()[0] == 'root']
    if root_procs:
        cr.findings.append(Finding(
            sev="CRITICAL",
            category="配置安全",
            title="Daemon 以 root 身份运行",
            detail=f"发现 {len(root_procs)} 个以 root 运行的 openclaw 进程:\n"
                   + "\n".join("  " + l[:100] for l in root_procs),
            fix=(
                "停止当前进程:\n"
                "  openclaw stop\n\n"
                "以普通用户重启（不使用 sudo）:\n"
                "  openclaw start\n\n"
                "永远不要使用 sudo openclaw。如需监听低端口，使用 iptables 端口转发。"
            )
        ))
    elif lines:
        cr.findings.append(Finding(
            sev="PASS", category="配置安全",
            title="Daemon 未以 root 运行", detail="进程所有者为普通用户。", fix=""
        ))


def check_config_permissions(cr: CheckResult):
    if IS_WIN:
        return
    claw_dir = Path.home() / ".openclaw"
    if not claw_dir.exists():
        return  # 未找到配置目录，跳过

    # 目录权限
    dir_perm = file_perm_octal(claw_dir)
    if dir_perm is not None and dir_perm > 0o700:
        cr.findings.append(Finding(
            sev="CRITICAL",
            category="配置安全",
            title="配置目录权限过于宽松",
            detail=(
                f"~/.openclaw 当前权限: {oct(dir_perm)} — 其他用户可能可以读取。\n"
                f"该目录存储 API keys、tokens、记忆等高度敏感数据。"
            ),
            fix=(
                "chmod 700 ~/.openclaw\n"
                "find ~/.openclaw -type d -exec chmod 700 {} \\;\n"
                "find ~/.openclaw -type f -exec chmod 600 {} \\;"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="配置安全",
            title="配置目录权限正确", detail=f"~/.openclaw 权限: {oct(dir_perm) if dir_perm else 'N/A'}", fix=""
        ))

    # 检查配置文件
    bad_files = []
    for f in claw_dir.rglob("*"):
        if f.is_file():
            p = file_perm_octal(f)
            if p is not None and p > 0o600:
                bad_files.append((f, oct(p)))

    if bad_files:
        detail_lines = "\n".join(f"  {f} ({p})" for f, p in bad_files[:10])
        cr.findings.append(Finding(
            sev="HIGH",
            category="配置安全",
            title="配置文件权限过于宽松",
            detail=f"以下文件权限应为 600，当前过于宽松:\n{detail_lines}",
            fix="find ~/.openclaw -type f -exec chmod 600 {} \\;"
        ))


def check_api_keys_plaintext(cr: CheckResult):
    """检查 config.json 中是否存在明文 API 密钥"""
    claw_dir = Path.home() / ".openclaw"
    patterns = [
        (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API Key"),
        (r"sk-proj-[a-zA-Z0-9\-_]{20,}", "OpenAI Project Key"),
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
        (r"AIzaSy[a-zA-Z0-9\-_]{33}", "Google API Key"),
        (r"xoxb-[0-9]+-[0-9a-zA-Z\-]+", "Slack Bot Token"),
        (r"[0-9]+:AA[a-zA-Z0-9\-_]{33}", "Telegram Bot Token"),
    ]
    found = []
    search_files = list(claw_dir.glob("**/*.json")) + list(claw_dir.glob("**/*.env")) \
                   + list(claw_dir.glob("**/config*")) if claw_dir.exists() else []

    for fpath in search_files[:30]:
        try:
            text = fpath.read_text(errors="replace")
            for pat, name in patterns:
                if re.search(pat, text):
                    found.append(f"{fpath.name} — {name}")
        except Exception:
            pass

    if found:
        cr.findings.append(Finding(
            sev="HIGH",
            category="配置安全",
            title="配置文件中发现疑似明文 API 密钥",
            detail="以下文件中发现已知密钥格式:\n" + "\n".join("  " + f for f in found),
            fix=(
                "将密钥迁移到 600 权限的 .env 文件:\n"
                "  chmod 600 ~/.openclaw/.env\n\n"
                "macOS 使用系统密钥链（更安全）:\n"
                "  security add-generic-password -a openclaw -s anthropic -w 'sk-ant-...'\n\n"
                "永远不要将密钥提交到 git 仓库。"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="配置安全",
            title="配置文件中未发现已知密钥格式", detail="建议人工再次确认 config.json 内容。", fix=""
        ))


def check_shell_history(cr: CheckResult):
    if IS_WIN:
        return
    history_files = [
        Path.home() / ".bash_history",
        Path.home() / ".zsh_history",
        Path.home() / ".local/share/fish/fish_history",
        Path.home() / ".history",
    ]
    key_patterns = [
        r"sk-ant-[a-zA-Z0-9\-_]{10,}",
        r"sk-proj-[a-zA-Z0-9\-_]{10,}",
        r"sk-[a-zA-Z0-9]{20,}",
        r"ANTHROPIC_API_KEY\s*=\s*\S+",
        r"OPENAI_API_KEY\s*=\s*\S+",
        r"TELEGRAM.*TOKEN\s*=\s*\S+",
        r"DISCORD.*TOKEN\s*=\s*\S+",
    ]
    found_files = []
    for hf in history_files:
        if not hf.exists():
            continue
        try:
            text = hf.read_text(errors="replace")
            for pat in key_patterns:
                if re.search(pat, text, re.I):
                    found_files.append(hf.name)
                    break
        except Exception:
            pass

    if found_files:
        cr.findings.append(Finding(
            sev="CRITICAL",
            category="配置安全",
            title="Shell 历史记录中发现 API 密钥",
            detail=(
                f"在以下历史文件中发现疑似 API 密钥:\n"
                + "\n".join("  ~/."+f for f in found_files)
                + "\n\n立即轮换这些密钥，因为历史文件可能已被读取。"
            ),
            fix=(
                "1. 立即在对应平台轮换所有密钥（Anthropic/OpenAI 控制台）\n\n"
                "2. 清理历史记录 (zsh):\n"
                "   sed -i '/sk-ant/d; /API_KEY/d; /TOKEN=/d' ~/.zsh_history\n\n"
                "3. 预防: 在 ~/.zshrc 中添加:\n"
                "   setopt HIST_IGNORE_SPACE   # 以空格开头不记录\n"
                "   export HISTIGNORE='*API_KEY*:*TOKEN*:*SECRET*'  # bash"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="配置安全",
            title="Shell 历史中未发现已知密钥格式", detail="建议仍手动检查历史文件。", fix=""
        ))


# ── 2. 依赖漏洞 ───────────────────────────────────────
def check_openclaw_version(cr: CheckResult):
    rc, local_ver, _ = run("openclaw --version")
    if rc != 0:
        rc, local_ver, _ = run("openclaw -v")

    rc2, latest_ver, _ = run("npm view openclaw version")

    if rc != 0 or not local_ver:
        cr.findings.append(Finding(
            sev="INFO", category="依赖漏洞",
            title="无法检测 OpenClaw 版本",
            detail="openclaw 命令未找到或版本命令失败。可能是 git 安装方式。",
            fix="npm install -g openclaw  # 或检查 pnpm 全局安装"
        ))
        return

    # 去掉 v 前缀并比较
    local_clean = re.sub(r'^v', '', local_ver.split('\n')[0].strip())
    latest_clean = re.sub(r'^v', '', latest_ver.strip()) if rc2 == 0 else None

    if latest_clean and local_clean != latest_clean:
        try:
            lv = [int(x) for x in local_clean.split('.')]
            rv = [int(x) for x in latest_clean.split('.')]
            if rv > lv:
                diff = rv[1] - lv[1] if rv[0] == lv[0] else 99
                sev = "HIGH" if diff >= 2 else "MEDIUM"
                cr.findings.append(Finding(
                    sev=sev, category="依赖漏洞",
                    title=f"OpenClaw 版本过旧: {local_clean} → {latest_clean}",
                    detail=f"当前: {local_clean} | 最新: {latest_clean}\n落后 {diff} 个次要版本，可能包含已修复的安全漏洞。",
                    fix=f"npm update -g openclaw\n# 更新后验证: openclaw --version"
                ))
                return
        except ValueError:
            pass

    cr.findings.append(Finding(
        sev="PASS", category="依赖漏洞",
        title=f"OpenClaw 已是最新版本 ({local_clean})", detail="", fix=""
    ))


def check_node_version(cr: CheckResult):
    rc, ver, _ = run("node --version")
    if rc != 0:
        cr.findings.append(Finding(
            sev="INFO", category="依赖漏洞",
            title="未检测到 Node.js",
            detail="node 命令不在 PATH 中。",
            fix="https://nodejs.org — 安装 Node.js 22 LTS"
        ))
        return

    match = re.search(r'v?(\d+)\.(\d+)', ver)
    if not match:
        return
    major = int(match.group(1))

    eol_map = {16: "2023-09-11 ❌", 18: "2025-04-30 ❌", 20: "2026-04-30 ⚠", 22: "2027-04-30 ✓"}
    if major <= 16:
        cr.findings.append(Finding(
            sev="HIGH", category="依赖漏洞",
            title=f"Node.js {ver} 已 EOL，不再接收安全补丁",
            detail=f"Node.js {major}.x EOL 日期: {eol_map.get(major,'已过期')}。使用 EOL 版本意味着已知漏洞永远不会被修复。",
            fix=(
                "使用 nvm 升级:\n"
                "  nvm install 22 && nvm use 22 && nvm alias default 22\n\n"
                "macOS Homebrew:\n"
                "  brew install node@22 && brew link node@22 --force"
            )
        ))
    elif major == 18:
        cr.findings.append(Finding(
            sev="MEDIUM", category="依赖漏洞",
            title=f"Node.js {ver} 将于 2025-04-30 EOL",
            detail="建议升级到 Node.js 22 LTS（支持至 2027-04-30）。",
            fix="nvm install 22 && nvm use 22"
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="依赖漏洞",
            title=f"Node.js {ver} 版本健康",
            detail=f"EOL 日期: {eol_map.get(major, '未知')}", fix=""
        ))


def check_npm_audit(cr: CheckResult):
    """运行 npm audit 检查已知漏洞"""
    # 找到 openclaw npm 包路径
    rc, npm_root, _ = run("npm root -g")
    pkg_dirs = []
    if rc == 0 and npm_root:
        d = Path(npm_root) / "openclaw"
        if d.exists():
            pkg_dirs.append(str(d))

    # git 安装路径
    for d in [Path.home() / "openclaw", Path.home() / ".openclaw"]:
        if (d / "package.json").exists():
            pkg_dirs.append(str(d))

    if not pkg_dirs:
        cr.findings.append(Finding(
            sev="INFO", category="依赖漏洞",
            title="未找到 openclaw package.json，跳过 npm audit",
            detail="找不到安装目录，请手动运行: npm audit --prefix <openclaw路径>",
            fix=""
        ))
        return

    for pkg_dir in pkg_dirs[:1]:  # 只检查第一个
        rc, out, err = run(f"npm audit --json --prefix {pkg_dir}", timeout=30)
        if rc == -1:
            cr.findings.append(Finding(
                sev="INFO", category="依赖漏洞",
                title="npm audit 执行超时或失败",
                detail=f"请手动运行: npm audit --prefix {pkg_dir}",
                fix=""
            ))
            continue
        try:
            data = json.loads(out or err or "{}")
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            crit  = vulns.get("critical", 0)
            high  = vulns.get("high", 0)
            mod   = vulns.get("moderate", 0)
            low_v = vulns.get("low", 0)
            total = vulns.get("total", 0)

            if crit > 0:
                cr.findings.append(Finding(
                    sev="CRITICAL", category="依赖漏洞",
                    title=f"npm audit: {crit} 严重漏洞, {high} 高危漏洞",
                    detail=(
                        f"严重: {crit}  高危: {high}  中危: {mod}  低危: {low_v}  总计: {total}\n"
                        f"路径: {pkg_dir}"
                    ),
                    fix=(
                        f"npm audit fix --prefix {pkg_dir}\n"
                        "# 强制修复（可能有 breaking changes）:\n"
                        f"npm audit fix --force --prefix {pkg_dir}\n"
                        "# 或更新 openclaw:\n"
                        "npm update -g openclaw"
                    )
                ))
            elif high > 0:
                cr.findings.append(Finding(
                    sev="HIGH", category="依赖漏洞",
                    title=f"npm audit: {high} 高危漏洞",
                    detail=f"高危: {high}  中危: {mod}  低危: {low_v}  总计: {total}",
                    fix=f"npm audit fix --prefix {pkg_dir}"
                ))
            elif mod > 0:
                cr.findings.append(Finding(
                    sev="MEDIUM", category="依赖漏洞",
                    title=f"npm audit: {mod} 中危漏洞",
                    detail=f"中危: {mod}  低危: {low_v}  总计: {total}",
                    fix=f"npm audit fix --prefix {pkg_dir}"
                ))
            else:
                cr.findings.append(Finding(
                    sev="PASS", category="依赖漏洞",
                    title=f"npm audit: 无严重漏洞 (共 {total} 个低危)",
                    detail="", fix=""
                ))
        except (json.JSONDecodeError, KeyError):
            cr.findings.append(Finding(
                sev="INFO", category="依赖漏洞",
                title="npm audit 输出解析失败",
                detail=f"请手动运行: npm audit --prefix {pkg_dir}",
                fix=""
            ))


def check_lockfile(cr: CheckResult):
    dirs_to_check = [Path.home() / "openclaw", Path.home() / ".openclaw"]
    for d in dirs_to_check:
        if not (d / "package.json").exists():
            continue
        has_lock = (d / "package-lock.json").exists() or (d / "pnpm-lock.yaml").exists()
        if not has_lock:
            cr.findings.append(Finding(
                sev="MEDIUM", category="依赖漏洞",
                title=f"缺少锁文件: {d}",
                detail="没有 package-lock.json 或 pnpm-lock.yaml，每次安装可能拉取不同版本（供应链攻击风险）。",
                fix=f"cd {d} && npm install  # 生成 lockfile\ngit add package-lock.json"
            ))
        else:
            cr.findings.append(Finding(
                sev="PASS", category="依赖漏洞",
                title=f"锁文件存在: {d}", detail="", fix=""
            ))


# ── 3. 网络/端口暴露 ──────────────────────────────────
def check_port_binding(cr: CheckResult):
    if IS_WIN:
        rc, out, _ = run("netstat -ano")
    elif IS_MAC:
        rc, out, _ = run("lsof -i -P -n")
    else:
        rc, out, _ = run("ss -tlnp")

    if rc != 0:
        return

    # 找所有 node 监听的端口
    open_all = []  # 绑定 0.0.0.0 或 ::
    local_ok  = []  # 绑定 127.0.0.1

    for line in out.splitlines():
        if "LISTEN" not in line and not IS_MAC:
            continue
        # 匹配 0.0.0.0:PORT 或 :::PORT
        if re.search(r'(0\.0\.0\.0|:::|\*):(\d+)', line) and re.search(r'node|openclaw', line, re.I):
            m = re.search(r'(0\.0\.0\.0|:::|\*):(\d+)', line)
            if m:
                open_all.append(f"端口 {m.group(2)} 绑定 {m.group(1)} (所有接口)")
        elif re.search(r'127\.0\.0\.1:\d+', line) and re.search(r'node|openclaw', line, re.I):
            m = re.search(r'127\.0\.0\.1:(\d+)', line)
            if m:
                local_ok.append(f"端口 {m.group(1)} 绑定 127.0.0.1 ✓")

    if open_all:
        cr.findings.append(Finding(
            sev="CRITICAL", category="网络暴露",
            title=f"服务端口对外暴露（局域网可访问）",
            detail=(
                "以下 Node.js 服务绑定到所有接口，局域网中的任何设备均可访问:\n"
                + "\n".join("  " + l for l in open_all)
            ),
            fix=(
                "在启动时强制绑定本地地址:\n"
                "  HOST=127.0.0.1 openclaw start\n\n"
                "远程访问使用 SSH 本地端口转发:\n"
                "  ssh -L 3000:127.0.0.1:3000 user@remote-host -N"
            )
        ))
    if local_ok:
        cr.findings.append(Finding(
            sev="PASS", category="网络暴露",
            title="监听中的服务绑定 127.0.0.1",
            detail="\n".join("  " + l for l in local_ok), fix=""
        ))


def check_firewall(cr: CheckResult):
    if IS_MAC:
        rc, out, _ = run("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
        if rc == 0:
            enabled = "enabled" in out.lower()
            if not enabled:
                cr.findings.append(Finding(
                    sev="HIGH", category="网络暴露",
                    title="macOS 应用防火墙未启用",
                    detail="系统防火墙关闭，无法阻止未授权的入站连接。",
                    fix="sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"
                ))
            else:
                cr.findings.append(Finding(
                    sev="PASS", category="网络暴露",
                    title="macOS 防火墙已启用", detail="", fix=""
                ))
    elif IS_LINUX:
        # 尝试 ufw
        rc, out, _ = run("sudo ufw status")
        if rc == 0:
            if "inactive" in out.lower():
                cr.findings.append(Finding(
                    sev="HIGH", category="网络暴露",
                    title="UFW 防火墙未启用",
                    detail="sudo ufw status 显示: inactive",
                    fix=(
                        "sudo ufw enable\n"
                        "sudo ufw default deny incoming\n"
                        "sudo ufw allow 22/tcp  # SSH"
                    )
                ))
            else:
                cr.findings.append(Finding(
                    sev="PASS", category="网络暴露",
                    title="UFW 防火墙已启用", detail="", fix=""
                ))


def check_cloudflared(cr: CheckResult):
    if not shutil.which("cloudflared"):
        return  # 未安装 cloudflared，跳过

    rc, ver, _ = run("cloudflared --version")
    # 检查是否使用临时 tunnel（trycloudflare.com）
    rc2, ps_out, _ = run("ps aux")
    if rc2 == 0 and "trycloudflare.com" in ps_out:
        cr.findings.append(Finding(
            sev="HIGH", category="网络暴露",
            title="使用临时 Cloudflare Tunnel URL (trycloudflare.com)",
            detail=(
                "检测到正在使用临时 Tunnel URL。\n"
                "任何知道该 URL 的人都可以直接访问你的 AI 助手，无需认证。"
            ),
            fix=(
                "创建命名 Tunnel 并配置 Cloudflare Access:\n"
                "  cloudflared tunnel login\n"
                "  cloudflared tunnel create openclaw\n"
                "  cloudflared tunnel route dns openclaw ai.yourdomain.com\n\n"
                "然后在 https://one.dash.cloudflare.com 配置 Access 身份认证。"
            )
        ))

    # 检查 cloudflared 版本
    rc3, latest_cf, _ = run("cloudflared update --check 2>&1")
    if "update available" in (latest_cf or "").lower():
        cr.findings.append(Finding(
            sev="MEDIUM", category="网络暴露",
            title=f"cloudflared 有可用更新",
            detail=latest_cf[:200],
            fix="cloudflared update"
        ))


def check_webhook_secret(cr: CheckResult):
    claw_dir = Path.home() / ".openclaw"
    if not claw_dir.exists():
        return

    # 搜索 webhook secret 配置
    found_secret = False
    for f in list(claw_dir.glob("**/*.json")) + list(claw_dir.glob("**/*.env")):
        try:
            text = f.read_text(errors="replace")
            if re.search(r'webhook.?secret|secret.?token|WEBHOOK_SECRET', text, re.I):
                found_secret = True
                break
        except Exception:
            pass

    if not found_secret:
        cr.findings.append(Finding(
            sev="HIGH", category="网络暴露",
            title="未找到 Webhook Secret 配置",
            detail=(
                "在 ~/.openclaw 中未找到 webhook secret / secret token 配置。\n"
                "未验证签名的 webhook 允许任何人伪造消息触发 AI 执行命令。"
            ),
            fix=(
                "生成 webhook secret:\n"
                "  openssl rand -hex 32\n\n"
                "Telegram 配置:\n"
                "  curl 'https://api.telegram.org/botTOKEN/setWebhook'\n"
                "       -d 'url=https://your-domain/webhook'\n"
                "       -d 'secret_token=YOUR_SECRET'\n\n"
                "确保 OpenClaw 的 webhook handler 验证该签名。"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="网络暴露",
            title="发现 Webhook Secret 配置", detail="请确认 secret 长度 ≥ 32 字符。", fix=""
        ))


# ── 4. 文件权限/敏感信息 ──────────────────────────────
def check_env_in_git(cr: CheckResult):
    git_dirs = [Path.home() / "openclaw", Path.home() / ".openclaw"]
    for d in git_dirs:
        if not (d / ".git").exists():
            continue
        rc, out, _ = run(f"git -C {d} ls-files .env config.json")
        if rc == 0 and out.strip():
            cr.findings.append(Finding(
                sev="HIGH", category="文件权限",
                title=f".env / config.json 被 git 跟踪: {d}",
                detail=(
                    f"以下文件被 git 跟踪（可能含有密钥）:\n"
                    + "\n".join("  " + l for l in out.splitlines())
                ),
                fix=(
                    f"cd {d}\n"
                    "git rm --cached .env config.json 2>/dev/null\n"
                    "echo '.env' >> .gitignore\n"
                    "echo 'config.json' >> .gitignore\n"
                    "git commit -m 'chore: remove secrets from git tracking'\n\n"
                    "如已推送到远程，立即轮换所有涉及的密钥！"
                )
            ))
        else:
            cr.findings.append(Finding(
                sev="PASS", category="文件权限",
                title=f".env 未被 git 跟踪: {d}", detail="", fix=""
            ))

        # 检查 git 历史
        rc2, hist, _ = run(
            f"git -C {d} log --all -p --max-count=200 2>/dev/null | "
            r"grep -iE '^\+.*(sk-ant|sk-proj|TELEGRAM.*TOKEN|OPENAI.*KEY)' | head -5",
            timeout=20
        )
        if rc2 == 0 and hist.strip():
            cr.findings.append(Finding(
                sev="CRITICAL", category="文件权限",
                title=f"Git 历史中发现曾提交过密钥: {d}",
                detail=(
                    "在 git 提交历史中发现疑似密钥（已隐藏实际值）。\n"
                    "即使后来删除，历史仍保留。"
                ),
                fix=(
                    "1. 立即轮换所有涉及的密钥\n\n"
                    "2. 清理 git 历史（仅限私有仓库）:\n"
                    "   pip3 install git-filter-repo\n"
                    "   git filter-repo --replace-text <(echo 'OLD_KEY==>REDACTED')\n\n"
                    "3. 强制推送: git push --force --all"
                )
            ))


def check_memory_files(cr: CheckResult):
    if IS_WIN:
        return
    claw_dir = Path.home() / ".openclaw"
    if not claw_dir.exists():
        return

    mem_dirs = [claw_dir / "memory", claw_dir / "context", claw_dir / "sessions"]
    for md in mem_dirs:
        if not md.exists():
            continue
        # 检查权限
        bad = []
        for f in md.rglob("*"):
            if f.is_file():
                p = file_perm_octal(f)
                if p and p > 0o600:
                    bad.append(str(f.name))
        if bad:
            cr.findings.append(Finding(
                sev="HIGH", category="文件权限",
                title=f"记忆文件权限过于宽松: {md}",
                detail=(
                    f"{md} 中 {len(bad)} 个文件权限高于 600。\n"
                    "记忆文件可能包含你的邮件、日历、财务等私人数据。"
                ),
                fix=(
                    f"find {md} -type f -exec chmod 600 {{}} \\;\n"
                    f"find {md} -type d -exec chmod 700 {{}} \\;"
                )
            ))
        else:
            cr.findings.append(Finding(
                sev="PASS", category="文件权限",
                title=f"记忆文件权限正确: {md}", detail="", fix=""
            ))


def check_log_leakage(cr: CheckResult):
    claw_dir = Path.home() / ".openclaw"
    log_dirs = [claw_dir / "logs", claw_dir]
    key_pattern = re.compile(
        r'(sk-ant-[a-zA-Z0-9]{10,}|Authorization:\s*Bearer\s+\S+|'
        r'sk-proj-[a-zA-Z0-9]{10,}|AIzaSy[a-zA-Z0-9]{33})',
        re.I
    )
    leaked = []
    for ld in log_dirs:
        if not ld.exists():
            continue
        for lf in list(ld.glob("*.log"))[:5]:
            try:
                # 只读最后 200 行
                with open(lf, errors="replace") as fh:
                    lines = fh.readlines()[-200:]
                for line in lines:
                    if key_pattern.search(line):
                        leaked.append(lf.name)
                        break
            except Exception:
                pass

    if leaked:
        cr.findings.append(Finding(
            sev="HIGH", category="文件权限",
            title=f"日志文件中发现 API 密钥或 Bearer Token",
            detail=f"在以下日志文件中发现疑似密钥:\n" + "\n".join("  " + f for f in leaked),
            fix=(
                "1. 降低日志级别:\n"
                "   LOG_LEVEL=warn openclaw start\n\n"
                "2. 修复现有日志权限:\n"
                "   chmod 600 ~/.openclaw/logs/*.log\n\n"
                "3. 轮换在日志中出现的密钥"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS", category="文件权限",
            title="日志文件中未发现已知密钥格式", detail="", fix=""
        ))


def check_cloud_sync(cr: CheckResult):
    if not IS_MAC:
        return
    claw_dir = Path.home() / ".openclaw"
    if not claw_dir.exists():
        return

    real = str(claw_dir.resolve())
    # 检查是否在 iCloud Drive 路径下
    icloud_paths = [
        str(Path.home() / "Library/Mobile Documents"),
        str(Path.home() / "iCloud Drive"),
    ]
    in_icloud = any(real.startswith(p) for p in icloud_paths)

    # 检查 Dropbox
    in_dropbox = str(Path.home() / "Dropbox") in real

    if in_icloud:
        cr.findings.append(Finding(
            sev="MEDIUM", category="文件权限",
            title="~/.openclaw 可能在 iCloud Drive 同步范围内",
            detail=(
                f"配置目录路径: {real}\n"
                "iCloud 可能正在将所有 API 密钥和记忆数据上传到云端。"
            ),
            fix=(
                "将 .openclaw 移出 iCloud 范围:\n"
                "  mv ~/.openclaw ~/Library/.openclaw_local\n"
                "  ln -s ~/Library/.openclaw_local ~/.openclaw\n\n"
                "或排除 Time Machine 备份:\n"
                "  sudo tmutil addexclusion ~/.openclaw"
            )
        ))
    else:
        # 检查 Time Machine 排除状态
        rc, tm_out, _ = run("sudo tmutil isexcluded ~/.openclaw 2>/dev/null")
        if rc == 0 and "excluded" not in tm_out.lower():
            cr.findings.append(Finding(
                sev="LOW", category="文件权限",
                title="~/.openclaw 未从 Time Machine 排除",
                detail="Time Machine 备份会包含所有 API 密钥（加密备份则可接受）。",
                fix="sudo tmutil addexclusion ~/.openclaw"
            ))


# ── 5. 系统级检查 ──────────────────────────────────────
def check_npm_global_perms(cr: CheckResult):
    if IS_WIN:
        return
    rc, npm_root, _ = run("npm root -g")
    if rc != 0 or not npm_root:
        return
    npm_path = Path(npm_root)
    p = file_perm_octal(npm_path)
    if p and is_world_readable(npm_path):
        cr.findings.append(Finding(
            sev="MEDIUM", category="依赖漏洞",
            title=f"npm 全局包目录对所有用户可读",
            detail=(
                f"{npm_root} 权限: {oct(p)}\n"
                "其他用户可读取安装的包文件（信息泄露风险）。"
            ),
            fix=(
                f"sudo chmod 755 {npm_root}  # 保持可执行但限制写\n"
                "# 或使用用户级 npm 安装（推荐）:\n"
                "# 参考 https://docs.npmjs.com/resolving-eacces-permissions-errors"
            )
        ))


# ══════════════════════════════════════════════════════
# 主程序
# ══════════════════════════════════════════════════════
ALL_CHECKS = [
    # 配置安全
    check_running_as_root,
    check_config_permissions,
    check_api_keys_plaintext,
    check_shell_history,
    # 依赖漏洞
    check_openclaw_version,
    check_node_version,
    check_npm_audit,
    check_lockfile,
    # 网络暴露
    check_port_binding,
    check_firewall,
    check_cloudflared,
    check_webhook_secret,
    # 文件权限
    check_env_in_git,
    check_memory_files,
    check_log_leakage,
    check_cloud_sync,
    # 系统
    check_npm_global_perms,
]

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "PASS": 5}
SEV_SCORE = {"CRITICAL": 20, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0, "PASS": 0}


def print_banner():
    print()
    print(BOLD(WHITE("  🦞  OpenClaw Security Audit Tool")))
    print(DIM("     仅用于检查自己的系统 | Defensive security only"))
    print(DIM("     openclaw.ai by @steipete"))
    print()


def print_progress(msg: str):
    print(DIM(f"  ⟳  {msg}"), end="\r")


def run_all_checks() -> List[Finding]:
    cr = CheckResult()
    for check_fn in ALL_CHECKS:
        label = check_fn.__name__.replace("check_", "").replace("_", " ")
        print_progress(f"检查: {label:<40}")
        try:
            check_fn(cr)
        except Exception as e:
            cr.findings.append(Finding(
                sev="INFO", category="系统",
                title=f"检查出错: {check_fn.__name__}",
                detail=str(e), fix=""
            ))
    print(" " * 60, end="\r")  # 清除进度行
    return cr.findings


def print_report(findings: List[Finding]):
    # 过滤掉 PASS，仅在摘要中统计
    issues = [f for f in findings if f.sev != "PASS"]
    passes = [f for f in findings if f.sev == "PASS"]

    # 按严重程度排序
    issues.sort(key=lambda f: SEV_ORDER.get(f.sev, 9))

    # 按 category 分组显示
    categories = {}
    for f in issues:
        cat = f.category or "其他"
        categories.setdefault(cat, []).append(f)

    # ── 分类输出 ──
    for cat, cat_findings in categories.items():
        print(BOLD(WHITE(f"\n{'━'*60}")))
        print(BOLD(WHITE(f"  {cat}")))
        print(BOLD(WHITE(f"{'━'*60}")))
        for f in cat_findings:
            print()
            print(f"  {sev_label(f.sev)}  {BOLD(f.title)}")
            if f.detail:
                for line in f.detail.splitlines():
                    print(DIM(f"             {line}"))
            if f.fix:
                print()
                print(GREEN("  修复建议:"))
                for line in f.fix.splitlines():
                    print(f"    {CYAN(line)}")

    # ── 通过项摘要 ──
    if passes:
        print(f"\n{'─'*60}")
        print(GREEN(f"  ✓  {len(passes)} 项检查通过:"))
        for p in passes:
            print(GREEN(f"     ✓ {p.title}"))

    # ── 评分 ──
    deductions = sum(SEV_SCORE.get(f.sev, 0) for f in issues)
    score = max(0, 100 - deductions)

    crits  = sum(1 for f in issues if f.sev == "CRITICAL")
    highs  = sum(1 for f in issues if f.sev == "HIGH")
    meds   = sum(1 for f in issues if f.sev == "MEDIUM")
    lows   = sum(1 for f in issues if f.sev == "LOW")

    print(f"\n{'━'*60}")
    print(BOLD(WHITE("  安全评分 / Security Score")))
    print(f"{'━'*60}")

    bar_len = 40
    filled = int(bar_len * score / 100)
    bar_color = GREEN if score >= 80 else (YELLOW if score >= 60 else (ORANGE if score >= 40 else RED))
    bar = bar_color("█" * filled) + DIM("░" * (bar_len - filled))
    print(f"\n  {bar}  {bar_color(BOLD(str(score) + '/100'))}\n")

    if crits: print(f"  {RED(f'● CRITICAL: {crits}')}")
    if highs: print(f"  {ORANGE(f'● HIGH:     {highs}')}")
    if meds:  print(f"  {YELLOW(f'● MEDIUM:   {meds}')}")
    if lows:  print(f"  {BLUE(f'● LOW:      {lows}')}")
    print(f"  {GREEN(f'● PASS:     {len(passes)}')}")

    print()
    if score == 100:
        print(GREEN("  🎉 太棒了！未发现已知安全问题。"))
    elif score >= 80:
        print(YELLOW("  ⚠  存在一些需要关注的问题，建议尽快修复高危项。"))
    elif score >= 60:
        print(ORANGE("  ⚠  存在多个安全问题，请按严重程度逐一修复。"))
    else:
        print(RED("  ✗  存在严重安全问题，请立即处理 CRITICAL 和 HIGH 级别漏洞！"))

    print()
    print(DIM("  提示: 修复后重新运行此脚本验证结果"))
    print(DIM("  文档: https://docs.openclaw.ai | 密钥轮换: https://console.anthropic.com"))
    print()


def main():
    print_banner()

    print(DIM(f"  系统: {platform.system()} {platform.release()} | Python {sys.version.split()[0]}"))
    rc, node_v, _ = run("node --version")
    if rc == 0:
        print(DIM(f"  Node:  {node_v}"))
    rc2, oc_v, _ = run("openclaw --version")
    if rc2 == 0:
        print(DIM(f"  OpenClaw: {oc_v.split(chr(10))[0]}"))

    claw_dirs = find_openclaw_dirs()
    if claw_dirs:
        print(DIM(f"  配置目录: {claw_dirs[0]}"))
    else:
        print(DIM("  配置目录: 未找到 ~/.openclaw"))
    print()

    print(WHITE("  开始扫描..."))
    findings = run_all_checks()
    print_report(findings)


if __name__ == "__main__":
    main()
