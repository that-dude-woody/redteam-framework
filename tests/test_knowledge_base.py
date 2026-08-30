"""Tests for core.knowledge_base — Finding storage, query, and data quality gates."""
import pytest
from core.knowledge_base import KnowledgeBase, Finding, ExploitLog


@pytest.fixture()
def kb():
    return KnowledgeBase(":memory:")


class TestAddFinding:
    def test_add_valid_finding(self, kb):
        f = Finding(phase="test", target="10.0.0.1", category="port", severity="info",
                    title="Open port 22", description="SSH detected")
        assert kb.add_finding(f) is True
        rows = kb.get_all_findings()
        assert len(rows) == 1
        assert rows[0].title == "Open port 22"

    def test_add_high_severity_no_description(self, kb):
        """High severity should not require description/evidence."""
        f = Finding(phase="test", target="10.0.0.2", category="vuln", severity="high",
                    title="SQL injection on login")
        assert kb.add_finding(f) is True

    def test_reject_empty_title(self, kb):
        f = Finding(target="10.0.0.1", category="port", severity="info", title="", description="desc")
        assert kb.add_finding(f) is False

    def test_reject_whitespace_title(self, kb):
        f = Finding(target="10.0.0.1", category="port", severity="info", title="   ", description="desc")
        assert kb.add_finding(f) is False

    def test_reject_info_no_description_or_evidence(self, kb):
        f = Finding(phase="test", target="10.0.0.3", category="port", severity="info",
                    title="Open port 80")
        assert kb.add_finding(f) is False

    def test_accept_low_with_evidence_only(self, kb):
        f = Finding(phase="test", target="10.0.0.4", category="service", severity="low",
                    title="HTTP service detected", evidence="<html>")
        assert kb.add_finding(f) is True

    def test_accept_critical_with_description_only(self, kb):
        f = Finding(phase="test", target="10.0.0.5", category="vuln", severity="critical",
                    title="RCE in web app", description="PoC available")
        assert kb.add_finding(f) is True

    def test_metadata_serialization(self, kb):
        f = Finding(phase="test", target="10.0.0.6", category="vuln", severity="high",
                    title="Test finding", description="Has metadata",
                    metadata={"cve": "CVE-2024-1234", "cvss": 9.8})
        kb.add_finding(f)
        rows = kb.get_findings(category="vuln")
        assert rows[0].metadata["cve"] == "CVE-2024-1234"


class TestAddFindings:
    def test_add_multiple(self, kb):
        findings = [
            Finding(phase="test", target=f"10.0.0.{i}", category="port", severity="info",
                    title=f"Port {i+80}", description=f"Service on port {i+80}")
            for i in range(5)
        ]
        kb.add_findings(findings)
        assert len(kb.get_all_findings()) == 5


class TestGetFindings:
    def test_get_all(self, kb):
        kb.add_finding(Finding(phase="test", target="10.0.0.1", category="port", severity="info",
                               title="P1", description="desc"))
        kb.add_finding(Finding(phase="test", target="10.0.0.2", category="vuln", severity="high",
                               title="P2", description="desc"))
        assert len(kb.get_all_findings()) == 2

    def test_filter_by_phase(self, kb):
        kb.add_finding(Finding(phase="a", target="10.0.0.1", category="port", severity="info",
                               title="A1", description="desc"))
        kb.add_finding(Finding(phase="b", target="10.0.0.2", category="vuln", severity="high",
                               title="B1", description="desc"))
        results = kb.get_findings(phases=["a"])
        assert len(results) == 1
        assert results[0].phase == "a"

    def test_filter_by_target(self, kb):
        kb.add_finding(Finding(phase="test", target="10.0.0.50", category="port", severity="info",
                               title="T1", description="desc"))
        results = kb.get_findings(target="10.0.0.50")
        assert len(results) == 1

    def test_filter_by_category(self, kb):
        kb.add_finding(Finding(phase="test", target="10.0.0.60", category="vuln", severity="high",
                               title="V1", description="desc"))
        results = kb.get_findings(category="vuln")
        assert len(results) == 1

    def test_filter_by_severity(self, kb):
        kb.add_finding(Finding(phase="test", target="10.0.0.70", category="port", severity="critical",
                               title="C1", description="desc"))
        results = kb.get_findings(severity="critical")
        assert len(results) == 1

    def test_filter_by_multiple_phases(self, kb):
        for phase in ("a", "b", "c"):
            kb.add_finding(Finding(phase=phase, target=f"10.0.0.{ord(phase)-96}", category="port",
                                   severity="info", title=f"{phase}1", description="desc"))
        results = kb.get_findings(phases=["a", "c"])
        assert len(results) == 2


class TestExploitLog:
    def test_add_and_query(self, kb):
        log = ExploitLog(target="10.0.0.1", technique="BruteForce_SSH", tool="hydra", status="success")
        kb.add_exploit_log(log)
        rows = kb.get_exploit_logs()
        assert len(rows) == 1
        assert rows[0].technique == "BruteForce_SSH"

    def test_filter_by_status(self, kb):
        kb.add_exploit_log(ExploitLog(target="t1", technique="T", tool="c", status="success"))
        kb.add_exploit_log(ExploitLog(target="t2", technique="T", tool="c", status="failure"))
        assert len(kb.get_exploit_logs(status="success")) == 1
        assert len(kb.get_exploit_logs(status="failure")) == 1

    def test_filter_by_target(self, kb):
        kb.add_exploit_log(ExploitLog(target="my-target", technique="T", tool="c", status="success"))
        rows = kb.get_exploit_logs(target="my-target")
        assert len(rows) == 1


class TestPhaseCompleted:
    def test_mark_and_retrieve(self, kb):
        kb.phase_completed("recon")
        status = kb.get_completion_status()
        assert "recon" in status

    def test_multiple_phases(self, kb):
        for phase in ("recon", "discovery", "exploitation"):
            kb.phase_completed(phase)
        status = kb.get_completion_status()
        assert len(status) == 3


class TestClearAll:
    def test_clear_fresh_kb(self, kb):
        kb.add_finding(Finding(phase="test", target="t1", category="port", severity="info",
                               title="F1", description="desc"))
        kb.add_exploit_log(ExploitLog(target="t1", technique="T", tool="c", status="success"))
        f_count, l_count = kb.clear_all()
        assert f_count == 1
        assert l_count == 1
        assert len(kb.get_all_findings()) == 0
        assert len(kb.get_exploit_logs()) == 0


class TestSummary:
    def test_empty_kb(self, kb):
        s = kb.summary()
        assert s["total_findings"] == 0
        assert s["total_exploit_logs"] == 0

    def test_with_data(self, kb):
        for i in range(3):
            sev = ["info", "low", "high"][i]
            kb.add_finding(Finding(phase="test", target=f"t{i}", category="port", severity=sev,
                                   title=f"F{i}", description="desc"))
        s = kb.summary()
        assert s["total_findings"] == 3
        assert s["findings_by_severity"]["high"] == 1


class TestDeleteFindings:
    def test_delete_by_category(self, kb):
        for cat in ("port", "vuln"):
            kb.add_finding(Finding(phase="test", target=f"t_{cat}", category=cat, severity="info",
                                   title=f"F_{cat}", description="desc"))
        count = kb.delete_findings_by_category("port")
        assert count == 1
        assert len(kb.get_findings(category="vuln")) == 1

    def test_delete_empty_title(self, kb):
        f1 = Finding(phase="test", target="t1", category="port", severity="info", title="", description="d")
        f2 = kb.add_finding(f1)
        assert f2 is False
        count = kb.delete_findings_with_empty_title()
        assert count == 0  # Nothing was inserted
