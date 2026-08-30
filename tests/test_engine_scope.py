"""Tests for engine run-scoping — prior findings from previous campaigns must
never reach phase handlers, while current-run rows and in-scope rows must."""

from datetime import datetime, timedelta, timezone

from core.config import FrameworkConfig
from core.engine import Engine
from core.knowledge_base import Finding, ExploitLog


def _stamp(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


def _now_stamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class RecordingPhase:
    """Phase handler that records exactly what snapshot it was handed."""

    instances = []

    def __init__(self, config, kb, cred_store, prior_findings, prior_exploit_logs):
        self.prior_findings = prior_findings
        self.prior_exploit_logs = prior_exploit_logs
        RecordingPhase.instances.append(self)

    def build_task_list(self):
        return []

    def execute_task(self, task):
        pass


def make_engine(tmp_path, targets):
    cfg = FrameworkConfig(db_path=str(tmp_path / "scope_engine.db"))
    cfg.target.targets = list(targets)
    for phase in cfg.phases:
        cfg.phases[phase].enabled = False
    eng = Engine(cfg)
    RecordingPhase.instances = []
    eng._load_phase_module = lambda name: RecordingPhase
    return eng


class TestScopeFilter:
    def test_phase_snapshot_excludes_stale_targets(self, tmp_path):
        eng = make_engine(tmp_path, targets=["example.com"])
        eng.kb.add_finding(Finding(
            phase="recon", target="73.170.57.26", category="host",
            severity="info", title="stale", description="d", timestamp=_stamp(30)))
        eng.kb.add_finding(Finding(
            phase="recon", target="ozlink.jizzing.space", category="host",
            severity="info", title="stale2", description="d", timestamp=_stamp(30)))
        eng.kb.add_finding(Finding(
            phase="recon", target="api.example.com", category="host",
            severity="info", title="in-scope", description="d", timestamp=_stamp(30)))

        eng.run_single("recon")

        received = RecordingPhase.instances[-1].prior_findings
        kept = {f.target for f in received}
        assert "73.170.57.26" not in kept
        assert "ozlink.jizzing.space" not in kept
        assert "api.example.com" in kept

    def test_phase_snapshot_keeps_current_run_rows(self, tmp_path):
        eng = make_engine(tmp_path, targets=["example.com"])
        eng.kb.add_finding(Finding(
            phase="discovery", target="10.0.0.5", category="service",
            severity="info", title="fresh", description="d", timestamp=_now_stamp()))
        eng.kb.add_finding(Finding(
            phase="recon", target="mysmartscaping.com", category="host",
            severity="info", title="stale", description="d", timestamp=_stamp(60)))

        eng.run_single("recon")

        received = RecordingPhase.instances[-1].prior_findings
        kept = {f.target for f in received}
        assert "10.0.0.5" in kept      # created during this run
        assert "mysmartscaping.com" not in kept  # stale + out of scope

    def test_filter_logs_same_policy(self, tmp_path):
        eng = make_engine(tmp_path, targets=["example.com"])
        eng.kb.add_exploit_log(ExploitLog(
            target="73.170.57.26", technique="BruteForce_SSH", tool="hydra",
            status="success", timestamp=_stamp(30)))
        eng.kb.add_exploit_log(ExploitLog(
            target="api.example.com", technique="SSH_Pivot", tool="sshpass",
            status="success", timestamp=_now_stamp()))

        eng.run_single("recon")

        received = RecordingPhase.instances[-1].prior_exploit_logs
        kept = {l.target for l in received}
        assert "73.170.57.26" not in kept
        assert "api.example.com" in kept

    def test_empty_scope_keeps_only_current_run(self, tmp_path):
        eng = make_engine(tmp_path, targets=[])
        eng.kb.add_finding(Finding(
            phase="recon", target="old.example.com", category="host",
            severity="info", title="s", description="d", timestamp=_stamp(30)))
        eng.kb.add_finding(Finding(
            phase="recon", target="new.local", category="host",
            severity="info", title="s", description="d", timestamp=_now_stamp()))

        eng.run_single("recon")

        received = RecordingPhase.instances[-1].prior_findings
        assert {f.target for f in received} == {"new.local"}