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