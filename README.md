# 🦞 openclaw-audit

> A security audit tool for [OpenClaw](https://openclaw.ai) — the self-hosted personal AI assistant.

OpenClaw runs on your own machine with full system access (bash, file I/O, browser control, 24/7 daemon). This tool automatically scans your installation for common misconfigurations and known vulnerabilities, then gives you actionable fix commands.

```
  🦞  OpenClaw Security Audit Tool

  系统: macOS 15.2 | Python 3.12
  Node:  v22.14.0
  OpenClaw: 1.8.3
  配置目录: ~/.openclaw

  开始扫描...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  配置安全
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [CRITICAL]  配置目录权限过于宽松
              ~/.openclaw 当前权限: 0o755 — 其他用户可能可以读取。

  修复建议:
    chmod 700 ~/.openclaw
    find ~/.openclaw -type f -exec chmod 600 {} \;

  ✓  Shell 历史中未发现已知密钥格式
  ✓  配置文件中未发现已知密钥格式
  ✓  Node.js v22.14.0 版本健康

  ████████████████████████████░░░░  75/100
  ● CRITICAL: 1  ● HIGH: 1  ● PASS: 8
```

## Features

- **Zero dependencies** — pure Python 3 standard library, no `pip install` needed
- **17 security checks** across 4 categories
- **Actionable fixes** — every finding comes with exact commands to run
- **Scoring system** — 0–100 score, deducted per unfixed issue
- **Cross-platform** — macOS, Linux, Windows (partial)
- **No network calls** — runs entirely offline, nothing leaves your machine

## Checks

### ⚙️ Configuration Security
| Check | Severity |
|---|---|
| Daemon running as root | CRITICAL |
| Config directory permissions (`~/.openclaw` should be `700`) | CRITICAL |
| API keys stored in plaintext in config files | HIGH |
| API keys found in shell history (`~/.zsh_history`, `~/.bash_history`) | CRITICAL |

### 📦 Dependency Vulnerabilities
| Check | Severity |
|---|---|
| `npm audit` — critical/high CVEs in installed packages | CRITICAL/HIGH |
| OpenClaw version outdated | HIGH/MEDIUM |
| Node.js EOL version (no more security patches) | HIGH |
| Missing lockfile (supply chain risk) | MEDIUM |

### 🌐 Network Exposure
| Check | Severity |
|---|---|
| Daemon port bound to `0.0.0.0` (LAN-accessible) | CRITICAL |
| Host firewall disabled | HIGH |
| Cloudflare Tunnel without Access authentication | HIGH |
| Webhook endpoint missing signature verification | HIGH |

### 🔑 File Permissions & Data Leakage
| Check | Severity |
|---|---|
| `.env` / `config.json` tracked in git | HIGH |
| API keys committed to git history | CRITICAL |
| Memory/context files world-readable | HIGH |
| API keys or Bearer tokens in log files | HIGH |
| Config directory synced to iCloud/Dropbox | MEDIUM |

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/openclaw-audit.git
cd openclaw-audit

# Run (no pip install needed)
python3 openclaw_audit.py
```

Or run directly without cloning:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/openclaw-audit/main/openclaw_audit.py | python3
```

## Requirements

- Python 3.8+
- That's it. No third-party packages.

Optional (for richer output):
- `npm` in PATH — enables `npm audit` and version checks
- `node` in PATH — enables Node.js EOL check
- `openclaw` in PATH — enables version comparison
- `cloudflared` in PATH — enables Cloudflare Tunnel checks
- `git` in PATH — enables git history scanning

## Output Explanation

```
[CRITICAL]  Issue title
            Detail about what was found and why it matters

  修复建议:
    exact command to fix it
```

Severity levels:
- **CRITICAL** — immediate risk, fix now (score -20 each)
- **HIGH** — significant risk, fix soon (score -10 each)
- **MEDIUM** — moderate risk, fix when possible (score -5 each)
- **LOW** — minor risk or best practice (score -2 each)
- **INFO** — informational, check skipped (no score impact)
- **PASS** — check passed ✓

## Usage Options

```bash
# Standard run
python3 openclaw_audit.py

# No color output (for logging/CI)
NO_COLOR=1 python3 openclaw_audit.py

# Save report to file
python3 openclaw_audit.py > audit-report.txt 2>&1

# Pipe to less for easy scrolling
python3 openclaw_audit.py | less -R
```

## Security Philosophy

OpenClaw is a powerful tool — it has:
- Full shell access (`bash` skill)
- File system read/write
- Browser automation
- 24/7 daemon running on your machine
- Access to your email, calendar, and personal data via memory

This attack surface is large. Common issues we've seen:
1. Running the daemon as root (`sudo openclaw`)
2. Loose permissions on `~/.openclaw` (755 instead of 700)
3. API keys in shell history from copy-pasting setup commands
4. Webhook endpoints accepting unsigned requests
5. Config directory being synced to iCloud Drive

## Contributing

PRs welcome. To add a new check:

1. Write a function `check_your_check_name(cr: CheckResult)` in `openclaw_audit.py`
2. Append a `Finding` with the appropriate severity, detail, and fix
3. Add the function to the `ALL_CHECKS` list
4. Add a row to the checks table in this README

See existing checks for patterns to follow.

## Disclaimer

This tool is for **defensive security purposes only** — to help you audit your own OpenClaw installation. Do not use it against systems you do not own or have explicit permission to test.

This project is not affiliated with OpenClaw or Anthropic.

## License

MIT — see [LICENSE](LICENSE)
