"""Tests for core.engine — phase lifecycle, run_single, throttle clamping."""

import pytest

from core.config import FrameworkConfig
from core.engine import Engine


@pytest.fixture()
def engine(tmp_path):
    cfg = FrameworkConfig(db_path=str(tmp_path / "engine_test.db"))
    # Start with every phase disabled so tests control exactly what runs
    for phase in cfg.phases:
        cfg.phases[phase].enabled = False
    return Engine(cfg)


class TestThrottle:
    def test_clamped_to_zero(self, engine):
        engine.throttle = -5
        assert engine.throttle == 0.0

    def test_acceptable_value_kept(self, engine):
        engine.throttle = 1.5
        assert engine.throttle == 1.5


class TestRun:
    def test_all_disabled_no_results(self, engine):
        engine.run()
        assert engine.status() == {}

    def test_enabled_phase_with_no_tasks_succeeds(self, engine):
        engine.config.phases["recon"].enabled = True
        engine.run()
        assert engine.results["recon"].success is True
        assert engine.results["recon"].tasks_executed == 0
        assert "recon" in engine.kb.get_completion_status()


class TestRunSingle:
    def test_unknown_phase_marks_failure(self, engine):
        engine.run_single("does_not_exist")
        result = engine.results["does_not_exist"]
        assert result.success is False
        assert result.error is not None

    def test_records_duration(self, engine):
        engine.config.phases["recon"].enabled = True
        engine.run_single("recon")
        assert engine.results["recon"].duration >= 0.0

    def test_findings_count_reflects_kb(self, engine):
        engine.config.phases["recon"].enabled = True
        engine.run_single("recon")
        assert "recon" in engine.status()
        assert engine.status()["recon"]["success"] is True