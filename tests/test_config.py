"""Tests for core.config — FrameworkConfig, TargetConfig, PhaseConfig."""

import json
import tempfile
import unittest
from pathlib import Path

from core.config import FrameworkConfig, TargetConfig, PhaseConfig


class TestTargetConfig(unittest.TestCase):
    def test_defaults(self):
        t = TargetConfig()
        self.assertEqual(t.targets, [])
        self.assertEqual(t.target_os, "mixed")
        self.assertTrue(t.authorized)
        self.assertTrue(t.logging_enabled)
        self.assertIsNone(t.scope_file)


class TestPhaseConfig(unittest.TestCase):
    def test_defaults(self):
        p = PhaseConfig()
        self.assertTrue(p.enabled)
        self.assertEqual(p.timeout, 3600)
        self.assertEqual(p.max_threads, 4)
        self.assertEqual(p.options, {})

    def test_override(self):
        p = PhaseConfig(enabled=False, timeout=120, max_threads=8, options={"foo": "bar"})
        self.assertFalse(p.enabled)
        self.assertEqual(p.timeout, 120)
        self.assertEqual(p.max_threads, 8)
        self.assertEqual(p.options, {"foo": "bar"})


class TestFrameworkConfig(unittest.TestCase):
    def test_defaults(self):
        c = FrameworkConfig()
        self.assertEqual(c.operator_name, "operator")
        self.assertEqual(c.campaign_id, "CAMPAIGN-001")
        self.assertIn("recon", c.phases)
        self.assertIn("discovery", c.phases)
        self.assertIn("exploitation", c.phases)
        self.assertIn("exploit_logging", c.phases)
        self.assertIn("post_exploit", c.phases)
        self.assertIn("lateral_movement", c.phases)
        self.assertIn("exfiltration", c.phases)

    def test_load_default_config(self):
        from core.config import load_default_config
        cfg = load_default_config()
        self.assertIsInstance(cfg, FrameworkConfig)
        self.assertEqual(cfg.operator_name, "operator")

    def test_roundtrip_via_file(self):
        c = FrameworkConfig(
            operator_name="alice",
            campaign_id="CAMP-42",
        )
        c.target.targets = ["10.0.0.1", "10.0.0.2"]
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            path = f.name
            c.save(path)

        loaded = FrameworkConfig.from_file(path)
        self.assertEqual(loaded.operator_name, "alice")
        self.assertEqual(loaded.campaign_id, "CAMP-42")
        self.assertEqual(loaded.target.targets, ["10.0.0.1", "10.0.0.2"])

        Path(path).unlink()


class TestGetPhaseOrder(unittest.TestCase):
    def test_order(self):
        from core.config import get_phase_order
        expected = [
            "recon",
            "discovery",
            "altdns",
            "ffuf",
            "gobuster_vhost",
            "wpscan",
            "exploitation",
            "metasploit_integration",
            "searchsploit_enrichment",
            "exploit_logging",
            "post_exploit",
            "lateral_movement",
            "exfiltration",
        ]
        self.assertEqual(get_phase_order(), expected)


if __name__ == "__main__":
    unittest.main()
