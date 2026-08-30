"""Tests for core.reporting — JSON / Markdown / MITRE output from a mocked KB."""

import json

import pytest

from core.config import FrameworkConfig
from core.knowledge_base import Finding, ExploitLog
from core.reporting import Reporter


class FakeKB:
    """KB stand-in returning deterministic data without touching a database."""

    def __init__(self, findings, logs):
        self._findings = findings
        self._logs = logs

    def summary(self):
        return {
            "total_findings": len(self._findings),
            "total_exploit_logs": len(self._logs),
            "findings_by_severity": {"high": 1},
            "completed_phases": {"recon": "2026-01-01T00:00:00+00:00"},
        }

    def get_all_findings(self):
        return self._findings

    def get_exploit_logs(self):
        return self._logs


@pytest.fixture()
def config():
    cfg = FrameworkConfig(
        campaign_id="CAMP-TEST",
        operator_name="op",
        report_format=["json", "markdown"],
    )
    cfg.target.targets = ["example.com"]
    return cfg


@pytest.fixture()
def kb():
    return FakeKB(
        findings=[
            Finding(
                phase="recon",
                target="example.com",
                category="vulnerability",
                severity="high",
                title="SQL injection",
                description="login endpoint vulnerable",
                metadata={"cvss": 8.1},
            )
        ],
        logs=[
            ExploitLog(
                target="example.com",
                technique="SQLi",
                tool="sqlmap",
                status="success",
                access_level="user",
            )
        ],
    )


class TestGenerate:
    def test_markdown_contains_finding(self, tmp_path, monkeypatch, config, kb):
        monkeypatch.setattr("core.reporting.REPORTS_DIR", tmp_path)
        Reporter(config, kb).generate(["markdown"])
        md_files = [p for p in tmp_path.glob("*.md")]
        assert len(md_files) == 1
        content = md_files[0].read_text()
        assert "CAMP-TEST" in content
        assert "SQL injection" in content

    def test_json_roundtrip(self, tmp_path, monkeypatch, config, kb):
        monkeypatch.setattr("core.reporting.REPORTS_DIR", tmp_path)
        Reporter(config, kb).generate(["json"])
        json_files = [p for p in tmp_path.glob("*.json")]
        assert len(json_files) == 1
        payload = json.loads(json_files[0].read_text())
        assert payload["campaign_id"] == "CAMP-TEST"
        assert payload["findings"][0]["title"] == "SQL injection"
        assert payload["exploit_logs"][0]["technique"] == "SQLi"
        assert payload["summary"]["total_findings"] == 1


class TestMitre:
    def test_export_lines_and_mapping(self, tmp_path, monkeypatch, config, kb):
        monkeypatch.setattr("core.reporting.REPORTS_DIR", tmp_path)
        path = Reporter(config, kb).generate_mitre()
        lines = [ln for ln in path.read_text().strip().splitlines() if ln]
        assert len(lines) == 2  # one finding row + one exploit log row
        finding_row = json.loads(lines[0])
        assert finding_row["technique_id"] == "T1190"  # vulnerability category
        assert finding_row["target"] == "example.com"