"""Tests for phases.discovery — noise filtering, httpx dedup and single-run."""

from unittest.mock import MagicMock

from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase, Finding
from core.tool_executor import ToolResult
from phases.discovery import discovery


def make_handler(prior=None, targets=(), te=None):
    cfg = FrameworkConfig()
    cfg.target.targets = list(targets)
    kb = KnowledgeBase(":memory:")
    handler = discovery(cfg, kb, MagicMock(), list(prior or []), [])
    if te is not None:
        handler.te = te
    return handler


class TestNoiseFiltering:
    def test_is_dns_infra_positive(self):
        assert discovery._is_dns_infra("ns1.example.com")
        assert discovery._is_dns_infra("mail.example.com")
        assert discovery._is_dns_infra("a.gtld-servers.net")

    def test_is_dns_infra_negative(self):
        assert not discovery._is_dns_infra("app.example.com")
        assert not discovery._is_dns_infra("example.com")

    def test_resolve_targets_filters_noise(self):
        prior = [
            Finding(phase="recon", target="10.0.0.1", category="host",
                    severity="info", title="x", description="d"),
            Finding(phase="recon", target="ns1.example.com", category="dns_record",
                    severity="info", title="x", description="d"),
            Finding(phase="recon", target="app.example.com", category="dns_record",
                    severity="info", title="x", description="d"),
        ]
        handler = make_handler(prior=prior, targets=["example.com"])
        hosts = handler._resolve_targets()
        assert "app.example.com" in hosts
        assert "example.com" in hosts
        assert "10.0.0.1" not in hosts
        assert "ns1.example.com" not in hosts


class TestHttpx:
    def test_single_httpx_task_deduplicated(self):
        def fake_resolve(name):
            return "/opt/homebrew/bin/httpx" if name == "httpx" else None

        te = MagicMock()
        te.resolve_binary = MagicMock(side_effect=fake_resolve)
        prior = [
            Finding(phase="discovery", target="10.0.0.1", category="open_port",
                    severity="info", title="p80", description="d", metadata={"port": 80}),
            Finding(phase="discovery", target="10.0.0.1", category="open_port",
                    severity="info", title="p443", description="d", metadata={"port": 443}),
        ]
        handler = make_handler(prior=prior, te=te)
        tasks = handler.build_task_list()
        httpx_tasks = [t for t in tasks if t["action"] == "httpx_fingerprint"]
        assert len(httpx_tasks) == 1
        assert httpx_tasks[0]["targets"] == ["10.0.0.1"]

    def test_run_httpx_dedups_duplicate_urls(self):
        res = ToolResult(success=True, parsed=[
            {"url": "http://a.com", "status_code": 200, "tech": ["react"]},
            {"url": "http://a.com", "status_code": 200, "tech": ["react"]},
        ])
        te = MagicMock()
        te.resolve_binary = MagicMock(return_value="/opt/homebrew/bin/httpx")
        te.run = MagicMock(return_value=res)
        handler = make_handler(te=te, targets=["a.com"])
        handler.execute_task({"action": "httpx_fingerprint", "targets": ["a.com"]})
        web = handler.kb.get_findings(category="web_app")
        assert len(web) == 1
        assert web[0].title == "Web app http://a.com (HTTP 200)"

    def test_run_httpx_ignores_target_outside_scope(self):
        te = MagicMock()
        te.resolve_binary = MagicMock(return_value="/opt/homebrew/bin/httpx")
        te.run = MagicMock(return_value=ToolResult(success=True, parsed=[
            {"url": "http://unscoped.com", "status_code": 200, "tech": []},
        ]))
        # Scope says a.com; an unsolicited httpx probe of unscoped.com must be dropped
        handler = make_handler(te=te, targets=["a.com"])
        handler.execute_task({"action": "httpx_fingerprint", "targets": ["unscoped.com"]})
        assert handler.kb.get_findings(category="web_app") == []