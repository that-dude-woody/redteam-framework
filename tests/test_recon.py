"""Tests for phases.recon — strict scope: tasks derive from configured targets,
never from stale Knowledge Base state left by previous campaigns."""

from unittest.mock import MagicMock

from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase, Finding
from phases.recon import recon


class TestReconScope:
    def _handler(self, targets, stale_metadata=True):
        cfg = FrameworkConfig()
        cfg.target.targets = list(targets)
        kb = KnowledgeBase(":memory:")
        if stale_metadata:
            # Simulate a previous campaign leaving state behind
            kb.store_target_info("73.170.57.26", type="ip")
            kb.store_target_info("https://mysmartscaping.com", type="url")
            kb.add_finding(Finding(phase="recon", target="ozlink.jizzing.space",
                                   category="host", severity="info",
                                   title="old", description="d"))
        return recon(cfg, kb, MagicMock(), [], [])

    def test_builds_from_configured_targets_only(self):
        handler = self._handler(["_archive.example.com"])
        tasks = handler.build_task_list()
        task_targets = {t["target"] for t in tasks}
        assert task_targets == {"_archive.example.com"}

    def test_normalizes_urls_and_dedups(self):
        handler = self._handler(["example.com", "https://example.com/login"])
        tasks = handler.build_task_list()
        assert [t["target"] for t in tasks] == ["example.com"]

    def test_empty_config_no_tasks(self):
        handler = self._handler([])
        assert handler.build_task_list() == []