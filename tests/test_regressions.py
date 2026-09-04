"""Regression tests for bugs found during the codebase audit.

Each test pins a specific fix so future refactors can't silently reintroduce
the original failure (closed-connection crash, data wipes, mangled URLs,
dead API calls, and so on).
"""

import tempfile
import os
import json

import pytest

from core.credential_store import CredentialStore
from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase, Finding, ExploitLog
from core.tool_executor import ToolResult
from unittest.mock import MagicMock


# --------------------------------------------------------------------------- #
# get_discovered_targets: previously crashed with sqlite3.ProgrammingError
# --------------------------------------------------------------------------- #

class TestGetDiscoveredTargets:
    def test_fresh_db_does_not_crash(self):
        kb = KnowledgeBase(":memory:")
        assert kb.get_discovered_targets() == []

    def test_returns_stored_metadata_targets(self):
        kb = KnowledgeBase(":memory:")
        kb.store_target_info("example.com", type="domain")
        assert "example.com" in kb.get_discovered_targets()

    def test_fallback_to_recon_findings(self):
        kb = KnowledgeBase(":memory:")
        kb.add_finding(Finding(phase="recon", target="10.0.0.1", category="host",
                               severity="info", title="Host found", description="d"))
        assert "10.0.0.1" in kb.get_discovered_targets()


# --------------------------------------------------------------------------- #
# update_exploit_log_status: finalize_log used to wipe pending-log fields
# --------------------------------------------------------------------------- #

class TestUpdateExploitLogStatus:
    def test_preserves_other_fields(self):
        kb = KnowledgeBase(":memory:")
        kb.add_exploit_log(ExploitLog(target="t1", technique="BruteForce_SSH",
                                      tool="hydra", command="hydra -l root",
                                      status="pending", access_level="user"))
        log_id = kb.get_exploit_logs()[0].id
        assert kb.update_exploit_log_status(log_id, "success") is True
        row = kb.get_exploit_logs()[0]
        assert row.status == "success"
        assert row.technique == "BruteForce_SSH"
        assert row.tool == "hydra"
        assert row.access_level == "user"

    def test_missing_log_returns_false(self):
        kb = KnowledgeBase(":memory:")
        assert kb.update_exploit_log_status("does-not-exist", "success") is False


# --------------------------------------------------------------------------- #
# exploit_logging.finalize_log regression
# --------------------------------------------------------------------------- #

class TestExploitLoggingFinalize:
    def test_finalize_preserves_technique(self):
        from phases.exploit_logging import exploit_logging
        from unittest.mock import MagicMock

        kb = KnowledgeBase(":memory:")
        kb.add_exploit_log(ExploitLog(target="t1", technique="RCE", tool="nuclei",
                                      status="pending"))
        log_id = kb.get_exploit_logs()[0].id
        handler = exploit_logging(FrameworkConfig(), kb, MagicMock(), [], [])
        handler.execute_task({"action": "finalize_log", "log_id": log_id, "target": "t1"})
        row = kb.get_exploit_logs()[0]
        assert row.status == "success"
        assert row.technique == "RCE"


# --------------------------------------------------------------------------- #
# service_specific credentials were previously never consulted
# --------------------------------------------------------------------------- #

class TestServiceSpecificCreds:
    def test_service_specific_merged_and_deduped(self):
        db_fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(db_fd)
        json_path = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json_path.write(json.dumps({
            "default_windows": [["Administrator", "Pass1"]],
            "service_specific": {"smb": [["svc_backup", "Backup@2024"],
                                         ["Administrator", "Pass1"]]},
        }))
        json_path.close()
        try:
            store = CredentialStore(db_path=db_path, cred_json_path=json_path.name)
            creds = store.load_creds("smb")
            assert ["svc_backup", "Backup@2024"] in creds
            # "Administrator"/"Pass1" comes from both categories but must appear once
            assert creds.count(["Administrator", "Pass1"]) == 1
        finally:
            os.unlink(db_path)
            os.unlink(json_path.name)


# --------------------------------------------------------------------------- #
# phase _resolve_binary: previously returned True even for missing tools
# --------------------------------------------------------------------------- #

class TestPhaseResolveBinary:
    @pytest.mark.parametrize("module_name", ["altdns", "ffuf", "gobuster_vhost", "wpscan"])
    def test_missing_tool_returns_false(self, module_name):
        import importlib
        mod = importlib.import_module(f"phases.{module_name}")
        assert mod._resolve_binary("binary_that_does_not_exist_xyz_42") is False

    def test_present_tool_returns_true(self):
        from phases.wpscan import _resolve_binary
        assert _resolve_binary("sh") is True


# --------------------------------------------------------------------------- #
# exploitation nuclei: URLs were mangled by str.replace("://", "", 1)
# --------------------------------------------------------------------------- #

class TestNucleiUrlPreserved:
    def test_scheme_and_path_not_mangled(self):
        from phases.exploitation import exploitation
        from unittest.mock import MagicMock

        kb = KnowledgeBase(":memory:")
        handler = exploitation(FrameworkConfig(), kb, MagicMock(), [], [])
        captured = {}

        def fake_run(tool, args, **kwargs):
            captured["url"] = args[1]
            return ToolResult(success=False)

        handler.te.run = fake_run
        handler.execute_task({"action": "nuclei_scan",
                              "target": "https://example.com/login", "mode": "web"})
        assert captured["url"] == "https://example.com/login"

    def test_bare_host_gets_scheme(self):
        from phases.exploitation import exploitation
        from unittest.mock import MagicMock

        kb = KnowledgeBase(":memory:")
        handler = exploitation(FrameworkConfig(), kb, MagicMock(), [], [])
        captured = {}

        def fake_run(tool, args, **kwargs):
            captured["url"] = args[1]
            return ToolResult(success=False)

        handler.te.run = fake_run
        handler.execute_task({"action": "nuclei_scan",
                              "target": "example.com", "mode": "web"})
        assert captured["url"] == "http://example.com"


# --------------------------------------------------------------------------- #
# metasploit_integration: called APIs that no longer (or never) exist
# --------------------------------------------------------------------------- #

class TestMetasploitBuildTasks:
    def test_empty_kb_returns_empty_list(self):
        from phases.metasploit_integration import metasploit_integration
        kb = KnowledgeBase(":memory:")
        assert metasploit_integration.build_tasks(kb) == []

    def test_maps_discovered_service_to_module_with_port(self):
        from phases.metasploit_integration import metasploit_integration
        kb = KnowledgeBase(":memory:")
        kb.store_target_info("10.0.0.5", type="ip")
        kb.add_finding(Finding(phase="discovery", target="10.0.0.5", category="service",
                               severity="info", title="ssh", description="d",
                               metadata={"service_name": "ssh", "port": 22}))
        tasks = metasploit_integration.build_tasks(kb)
        assert any(t["target"] == "10.0.0.5" and t["port"] == 22 for t in tasks)

    def test_build_task_list_uses_scoped_snapshot_only(self):
        """Stale targets left in the live KB must not generate tasks when the
        engine-provided (scoped) snapshot doesn't include them."""
        from unittest.mock import MagicMock
        from phases.metasploit_integration import metasploit_integration

        kb = KnowledgeBase(":memory:")
        # Stale rows from a previous campaign still sitting in the DB:
        kb.add_finding(Finding(phase="discovery", target="73.170.57.26", category="service",
                               severity="info", title="ssh", description="d",
                               metadata={"service_name": "ssh", "port": 22}))
        # Engine-scoped snapshot for THIS run only contains an in-scope service:
        scoped = [Finding(phase="discovery", target="api.example.com", category="service",
                          severity="info", title="ssh", description="d",
                          metadata={"service_name": "ssh", "port": 22})]
        handler = metasploit_integration(FrameworkConfig(), kb, MagicMock(), scoped, [])
        tasks = handler.build_task_list()
        targets = {t["target"] for t in tasks}
        assert "api.example.com" in targets
        assert "73.170.57.26" not in targets


# --------------------------------------------------------------------------- #
# ffuf / gobuster_vhost / wpscan / altdns: their local `_run()`/`_exec_gobuster()`
# helpers return a raw subprocess.CompletedProcess, which exposes `.returncode`
# but NOT `.success`. The phases probed `res.success`, raising
#     AttributeError: 'CompletedProcess' object has no attribute 'success'
# for every task — so the engine logged each task as failed and the phases
# produced zero findings. Success must be checked via `.returncode == 0`.
# --------------------------------------------------------------------------- #

class TestLocalSubprocessRunReturncode:
    def _completed(self, rc=0, stdout="", stderr=""):
        import subprocess
        return subprocess.CompletedProcess(
            args=[], returncode=rc, stdout=stdout, stderr=stderr
        )

    def test_ffuf_success_path_produces_finding(self):
        from phases.ffuf import ffuf
        kb = KnowledgeBase(":memory:")
        h = ffuf(FrameworkConfig(), kb, MagicMock(), [], [])
        out = "[200]    123   4567  12345.6  http://know.shit.vc/admin\n"
        ffuf._run = staticmethod(lambda cmd, timeout=300: self._completed(0, out))
        # Before the fix this raised AttributeError; the success path now runs.
        h.execute_task({"action": "dir_fuzz", "url": "http://know.shit.vc"})
        assert any("admin" in f.title for f in kb.get_findings())

    def test_ffuf_binary_missing_returns_early(self):
        from phases.ffuf import ffuf
        kb = KnowledgeBase(":memory:")
        h = ffuf(FrameworkConfig(), kb, MagicMock(), [], [])
        ffuf._run = staticmethod(
            lambda cmd, timeout=300: self._completed(127, "", "binary not found"))
        h.execute_task({"action": "dir_fuzz", "url": "http://know.shit.vc"})
        assert kb.get_findings() == []

    def test_gobuster_vhost_both_modules_run_without_crash(self):
        from phases.gobuster_vhost import gobuster_vhost
        kb = KnowledgeBase(":memory:")
        h = gobuster_vhost(FrameworkConfig(), kb, MagicMock(), [], [])
        gobuster_vhost._run = staticmethod(
            lambda cmd, timeout=300:
            self._completed(0, "2026/08/18 10:00:00 [!] host Status: 200\n")
        )
        # Previously crashed at both `.success` sites (vhost + dir-fuzz).
        h.execute_task({"action": "vhost_discovery", "target": "know.shit.vc"})
        h.execute_task({"action": "dir_fuzz", "target": "know.shit.vc"})

    def test_gobuster_vhost_binary_missing_returns_early(self):
        from phases.gobuster_vhost import gobuster_vhost
        kb = KnowledgeBase(":memory:")
        h = gobuster_vhost(FrameworkConfig(), kb, MagicMock(), [], [])
        gobuster_vhost._run = staticmethod(
            lambda cmd, timeout=300: self._completed(127, "", "nope"))
        h.execute_task({"action": "vhost_discovery", "target": "know.shit.vc"})
        h.execute_task({"action": "dir_fuzz", "target": "know.shit.vc"})
        assert kb.get_findings() == []

    def test_wpscan_success_path_produces_finding(self):
        from phases.wpscan import wpscan
        kb = KnowledgeBase(":memory:")
        h = wpscan(FrameworkConfig(), kb, MagicMock(), [], [])
        out = "WPScan v3.8.21\nWordPress 6.0 detected at http://know.shit.vc\n"
        wpscan._run = staticmethod(lambda cmd, timeout=300: self._completed(0, out))
        h.execute_task({"action": "detect_wpsite", "url": "http://know.shit.vc"})
        assert any(f.category == "cms_detected" for f in kb.get_findings())

    def test_altdns_mutate_exercises_returncode_paths(self):
        import phases.altdns as altdns_mod
        from phases.altdns import altdns
        kb = KnowledgeBase(":memory:")
        h = altdns(FrameworkConfig(), kb, MagicMock(), [], [])
        orig = altdns_mod._resolve_binary
        altdns_mod._resolve_binary = lambda name: True
        altdns._run = staticmethod(
            lambda cmd, timeout=120: self._completed(0, "know.shit.vc\n"))
        try:
            # Drives both previously-buggy `.success` sites (altdns + massdns).
            h.execute_task({"action": "mutate", "domain": "know.shit.vc"})
        finally:
            altdns_mod._resolve_binary = orig


# --------------------------------------------------------------------------- #
# Wordlist resolution: the fuzz phases used to hardcode Linux-only SecLists
# paths (/usr/share/seclists/...), so on macOS -- where the lists live
# elsewhere -- ffuf/gobuster exited non-zero and the phases silently produced
# zero findings. Resolution must be configurable (SECLISTS_DIR) and find real
# files, failing safely (not raising) when none are present.
# --------------------------------------------------------------------------- #

class TestWordlistResolution:
    def test_resolves_from_seclists_dir(self, tmp_path, monkeypatch):
        import core.wordlists as w
        root = tmp_path / "SecLists"
        (root / "Discovery" / "Web-Content").mkdir(parents=True)
        (root / "Discovery" / "DNS").mkdir(parents=True)
        web = root / "Discovery" / "Web-Content" / "common.txt"
        web.write_text("admin\nlogin\n")
        dns = root / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
        dns.write_text("api\nadmin\n")
        # SECLISTS_DIR must take priority over any real machine wordlists.
        monkeypatch.setenv("SECLISTS_DIR", str(root))
        assert os.path.realpath(w.resolve("web")) == os.path.realpath(str(web))
        assert os.path.realpath(w.resolve("vhosts")) == os.path.realpath(str(dns))

    def test_missing_wordlist_fails_safe(self, tmp_path, monkeypatch):
        import core.wordlists as w
        # Point at an empty dir and disable every other root/legacy path.
        monkeypatch.setenv("SECLISTS_DIR", str(tmp_path))
        monkeypatch.setattr(w, "_ROOT_CANDIDATES", [])
        monkeypatch.setattr(w, "_LEGACY", {})
        # Must return a (non-existent) default path string instead of raising.
        result = w.resolve("web")
        assert isinstance(result, str) and result
        assert not os.path.isfile(result)
