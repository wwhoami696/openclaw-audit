# Contributing to openclaw-audit

Thanks for helping make OpenClaw safer for everyone.

## Adding a New Check

1. **Write the function** in `openclaw_audit.py`:

```python
def check_your_thing(cr: CheckResult):
    # Run a command or inspect the filesystem
    rc, out, _ = run("some command")

    if rc != 0 or "bad thing" in out:
        cr.findings.append(Finding(
            sev="HIGH",           # CRITICAL / HIGH / MEDIUM / LOW / INFO
            category="配置安全",  # or 依赖漏洞 / 网络暴露 / 文件权限
            title="Short title of what's wrong",
            detail=(
                "Explanation of what was found and why it's a problem.\n"
                f"Specific detail: {out[:100]}"
            ),
            fix=(
                "Exact command to fix it:\n"
                "  some fix command\n\n"
                "Optional: additional context or docs link"
            )
        ))
    else:
        cr.findings.append(Finding(
            sev="PASS",
            category="配置安全",
            title="Short description of what passed",
            detail="", fix=""
        ))
```

2. **Add it to `ALL_CHECKS`** near the bottom of the file.

3. **Write a test** in `tests/test_audit.py` — at minimum one test for the bad case and one for the clean case.

4. **Update the table** in `README.md`.

## Severity Guidelines

| Severity | When to use | Score impact |
|---|---|---|
| CRITICAL | Immediate exploitation risk; data already exposed | -20 |
| HIGH | Significant risk, exploitable under common conditions | -10 |
| MEDIUM | Notable risk, requires specific circumstances | -5 |
| LOW | Minor risk or best-practice violation | -2 |
| INFO | Check couldn't run (missing tool, etc.) | 0 |
| PASS | Check passed — always emit this when clean | 0 |

## Running Tests

```bash
# With pytest (recommended)
pip install pytest
python3 -m pytest tests/ -v

# With built-in unittest
python3 -m unittest tests/test_audit.py -v
```

## Style

- Keep the script a **single file** with zero dependencies
- Every check must handle exceptions gracefully (`try/except`)
- Fix commands should be **copy-pasteable** — exact, working commands
- Both Chinese and English in messages is intentional (mirrors OpenClaw's international user base)

## Reporting a False Positive

Open an issue with:
1. Your OS and Python version
2. The check name that fired incorrectly
3. What your actual configuration looks like

## Scope

This tool only checks things that are:
- Visible from the local filesystem or running processes
- Relevant to an OpenClaw self-hosted installation
- Defensively oriented (checking your own system)

Out of scope: active network scanning, exploiting vulnerabilities, checking other users' systems.
