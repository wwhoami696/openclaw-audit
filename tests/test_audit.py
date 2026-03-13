"""
Tests for openclaw_audit.py
Run with: python3 -m pytest tests/ -v
"""

import os
import sys
import stat
import json
import tempfile
import textwrap
from pathlib import Path
from unittest import mock
from unittest.mock import patch, MagicMock

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import openclaw_audit as audit
from openclaw_audit import (
    CheckResult, Finding,
    check_running_as_root,
    check_config_permissions,
    check_api_keys_plaintext,
    check_shell_history,
    check_openclaw_version,
    check_node_version,
    check_npm_audit,
    check_lockfile,
    check_port_binding,
    check_env_in_git,
    check_log_leakage,
    check_memory_files,
)


# ─── Helpers ────────────────────────────────────────────────────────────
def get_findings(cr: CheckResult, sev=None) -> list[Finding]:
    if sev:
        return [f for f in cr.findings if f.sev == sev]
    return cr.findings

def has_sev(cr: CheckResult, sev: str) -> bool:
    return any(f.sev == sev for f in cr.findings)


# ─── check_running_as_root ───────────────────────────────────────────────
class TestRunningAsRoot:
    def test_no_openclaw_process(self):
        cr = CheckResult()
        with patch("openclaw_audit.run", return_value=(0, "user 1234 0.0 node server.js", "")):
            check_running_as_root(cr)
        # No openclaw process → no findings added (check looks for 'openclaw|claw')
        assert not has_sev(cr, "CRITICAL")

    def test_root_process_detected(self):
        cr = CheckResult()
        fake_ps = "root 999 0.1 0.0 openclaw --daemon"
        with patch("openclaw_audit.run", return_value=(0, fake_ps, "")):
            with patch("os.getpid", return_value=0):
                check_running_as_root(cr)
        assert has_sev(cr, "CRITICAL")
        assert "root" in cr.findings[0].detail.lower()

    def test_normal_user_process(self):
        cr = CheckResult()
        fake_ps = "alice 999 0.1 0.0 openclaw --daemon"
        with patch("openclaw_audit.run", return_value=(0, fake_ps, "")):
            with patch("os.getpid", return_value=0):
                check_running_as_root(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "CRITICAL")


# ─── check_config_permissions ────────────────────────────────────────────
class TestConfigPermissions:
    def test_correct_permissions(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir()
        claw_dir.chmod(0o700)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_config_permissions(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "CRITICAL")

    def test_loose_dir_permissions(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir()
        claw_dir.chmod(0o755)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_config_permissions(cr)
        assert has_sev(cr, "CRITICAL")

    def test_loose_file_permissions(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir(mode=0o700)
        config = claw_dir / "config.json"
        config.write_text('{"test": 1}')
        config.chmod(0o644)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_config_permissions(cr)
        assert has_sev(cr, "HIGH")

    def test_no_openclaw_dir(self, tmp_path):
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_config_permissions(cr)
        # Should not crash, no findings
        assert len(cr.findings) == 0


# ─── check_api_keys_plaintext ─────────────────────────────────────────────
class TestApiKeysPlaintext:
    def test_anthropic_key_detected(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir(mode=0o700)
        config = claw_dir / "config.json"
        config.write_text(json.dumps({"apiKey": "sk-ant-api03-FAKEKEYFORTESTING1234567890abcdef"}))
        config.chmod(0o600)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_api_keys_plaintext(cr)
        assert has_sev(cr, "HIGH")

    def test_no_keys_clean(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir(mode=0o700)
        config = claw_dir / "config.json"
        config.write_text(json.dumps({"model": "claude-sonnet-4-6", "logLevel": "warn"}))
        config.chmod(0o600)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_api_keys_plaintext(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "HIGH")

    def test_openai_key_detected(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir(mode=0o700)
        config = claw_dir / "config.json"
        config.write_text('{"key": "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234"}')
        config.chmod(0o600)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_api_keys_plaintext(cr)
        assert has_sev(cr, "HIGH")


# ─── check_shell_history ─────────────────────────────────────────────────
class TestShellHistory:
    def test_key_in_history(self, tmp_path):
        hist = tmp_path / ".zsh_history"
        hist.write_text(": 1700000000:0;ANTHROPIC_API_KEY=sk-ant-api03-FAKEFAKEFAKE openclaw start\n")
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_shell_history(cr)
        assert has_sev(cr, "CRITICAL")

    def test_clean_history(self, tmp_path):
        hist = tmp_path / ".bash_history"
        hist.write_text("ls -la\ncd projects\ngit status\n")
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_shell_history(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "CRITICAL")

    def test_no_history_files(self, tmp_path):
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_shell_history(cr)
        assert has_sev(cr, "PASS")


# ─── check_node_version ──────────────────────────────────────────────────
class TestNodeVersion:
    def test_eol_node_16(self):
        cr = CheckResult()
        with patch("openclaw_audit.run", return_value=(0, "v16.20.2", "")):
            check_node_version(cr)
        assert has_sev(cr, "HIGH")

    def test_eol_node_18(self):
        cr = CheckResult()
        with patch("openclaw_audit.run", return_value=(0, "v18.20.0", "")):
            check_node_version(cr)
        assert has_sev(cr, "MEDIUM")

    def test_healthy_node_22(self):
        cr = CheckResult()
        with patch("openclaw_audit.run", return_value=(0, "v22.1.0", "")):
            check_node_version(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "HIGH")

    def test_node_not_found(self):
        cr = CheckResult()
        with patch("openclaw_audit.run", return_value=(1, "", "command not found")):
            check_node_version(cr)
        assert has_sev(cr, "INFO")


# ─── check_npm_audit ─────────────────────────────────────────────────────
class TestNpmAudit:
    def _make_audit_json(self, critical=0, high=0, moderate=0, low=0):
        total = critical + high + moderate + low
        return json.dumps({
            "metadata": {
                "vulnerabilities": {
                    "critical": critical,
                    "high": high,
                    "moderate": moderate,
                    "low": low,
                    "total": total,
                }
            }
        })

    def test_critical_vuln(self, tmp_path):
        pkg = tmp_path / "openclaw"
        pkg.mkdir()
        (pkg / "package.json").write_text('{"name":"openclaw"}')
        cr = CheckResult()
        audit_out = self._make_audit_json(critical=2, high=1)
        with patch("openclaw_audit.run") as mock_run:
            mock_run.side_effect = [
                (0, str(tmp_path), ""),   # npm root -g
                (1, audit_out, ""),        # npm audit
            ]
            with patch("openclaw_audit.Path.home", return_value=tmp_path):
                check_npm_audit(cr)
        assert has_sev(cr, "CRITICAL")

    def test_no_vulns(self, tmp_path):
        pkg = tmp_path / "openclaw"
        pkg.mkdir()
        (pkg / "package.json").write_text('{"name":"openclaw"}')
        cr = CheckResult()
        audit_out = self._make_audit_json()
        with patch("openclaw_audit.run") as mock_run:
            mock_run.side_effect = [
                (0, str(tmp_path), ""),
                (0, audit_out, ""),
            ]
            with patch("openclaw_audit.Path.home", return_value=tmp_path):
                check_npm_audit(cr)
        assert has_sev(cr, "PASS")


# ─── check_lockfile ──────────────────────────────────────────────────────
class TestLockfile:
    def test_missing_lockfile(self, tmp_path):
        d = tmp_path / "openclaw"
        d.mkdir()
        (d / "package.json").write_text('{"name":"openclaw"}')
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_lockfile(cr)
        assert has_sev(cr, "MEDIUM")

    def test_lockfile_present(self, tmp_path):
        d = tmp_path / "openclaw"
        d.mkdir()
        (d / "package.json").write_text('{"name":"openclaw"}')
        (d / "package-lock.json").write_text('{}')
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_lockfile(cr)
        assert has_sev(cr, "PASS")


# ─── check_port_binding ──────────────────────────────────────────────────
class TestPortBinding:
    def test_exposed_port(self):
        cr = CheckResult()
        fake_lsof = textwrap.dedent("""
            node    1234 user  21u  IPv4  0t0  TCP 0.0.0.0:3000 (LISTEN)
        """)
        with patch("openclaw_audit.run", return_value=(0, fake_lsof, "")):
            with patch("openclaw_audit.IS_WIN", False):
                with patch("openclaw_audit.IS_MAC", True):
                    check_port_binding(cr)
        assert has_sev(cr, "CRITICAL")

    def test_local_only_port(self):
        cr = CheckResult()
        fake_lsof = textwrap.dedent("""
            node    1234 user  21u  IPv4  0t0  TCP 127.0.0.1:3000 (LISTEN)
        """)
        with patch("openclaw_audit.run", return_value=(0, fake_lsof, "")):
            with patch("openclaw_audit.IS_WIN", False):
                with patch("openclaw_audit.IS_MAC", True):
                    check_port_binding(cr)
        assert has_sev(cr, "PASS")
        assert not has_sev(cr, "CRITICAL")


# ─── check_env_in_git ────────────────────────────────────────────────────
class TestEnvInGit:
    def test_env_tracked(self, tmp_path):
        d = tmp_path / "openclaw"
        d.mkdir()
        (d / ".git").mkdir()
        (d / ".env").write_text("ANTHROPIC_API_KEY=sk-ant-fake")
        cr = CheckResult()
        with patch("openclaw_audit.run") as mock_run:
            mock_run.side_effect = [
                (0, ".env", ""),   # git ls-files
                (0, "", ""),       # git log (no history keys)
            ]
            with patch("openclaw_audit.Path.home", return_value=tmp_path):
                check_env_in_git(cr)
        assert has_sev(cr, "HIGH")

    def test_env_not_tracked(self, tmp_path):
        d = tmp_path / "openclaw"
        d.mkdir()
        (d / ".git").mkdir()
        cr = CheckResult()
        with patch("openclaw_audit.run") as mock_run:
            mock_run.side_effect = [
                (0, "", ""),   # git ls-files — empty
                (0, "", ""),   # git log
            ]
            with patch("openclaw_audit.Path.home", return_value=tmp_path):
                check_env_in_git(cr)
        assert has_sev(cr, "PASS")


# ─── check_log_leakage ────────────────────────────────────────────────────
class TestLogLeakage:
    def test_key_in_log(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir()
        logs_dir = claw_dir / "logs"
        logs_dir.mkdir()
        log = logs_dir / "app.log"
        log.write_text("2026-01-01 INFO Authorization: Bearer sk-ant-api03-FAKEKEYFAKEKEYFAKEFAKE\n")
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_log_leakage(cr)
        assert has_sev(cr, "HIGH")

    def test_clean_log(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        claw_dir.mkdir()
        logs_dir = claw_dir / "logs"
        logs_dir.mkdir()
        log = logs_dir / "app.log"
        log.write_text("2026-01-01 INFO Server started on port 3000\n2026-01-01 WARN Rate limit hit\n")
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_log_leakage(cr)
        assert has_sev(cr, "PASS")


# ─── check_memory_files ──────────────────────────────────────────────────
class TestMemoryFiles:
    def test_loose_memory_perms(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        mem_dir = claw_dir / "memory"
        mem_dir.mkdir(parents=True)
        mem_file = mem_dir / "memory.json"
        mem_file.write_text('{"memories": []}')
        mem_file.chmod(0o644)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_memory_files(cr)
        assert has_sev(cr, "HIGH")

    def test_correct_memory_perms(self, tmp_path):
        claw_dir = tmp_path / ".openclaw"
        mem_dir = claw_dir / "memory"
        mem_dir.mkdir(parents=True)
        mem_file = mem_dir / "memory.json"
        mem_file.write_text('{"memories": []}')
        mem_file.chmod(0o600)
        cr = CheckResult()
        with patch("openclaw_audit.Path.home", return_value=tmp_path):
            check_memory_files(cr)
        assert has_sev(cr, "PASS")


# ─── Scoring ─────────────────────────────────────────────────────────────
class TestScoring:
    def test_perfect_score(self):
        findings = [Finding(sev="PASS", title="ok", detail="", fix="")]
        deductions = sum(audit.SEV_SCORE.get(f.sev, 0) for f in findings if f.sev != "PASS")
        assert max(0, 100 - deductions) == 100

    def test_critical_deducts_20(self):
        findings = [Finding(sev="CRITICAL", title="bad", detail="", fix="")]
        deductions = sum(audit.SEV_SCORE.get(f.sev, 0) for f in findings)
        assert max(0, 100 - deductions) == 80

    def test_score_floor_zero(self):
        findings = [Finding(sev="CRITICAL", title=f"c{i}", detail="", fix="") for i in range(10)]
        deductions = sum(audit.SEV_SCORE.get(f.sev, 0) for f in findings)
        assert max(0, 100 - deductions) == 0
