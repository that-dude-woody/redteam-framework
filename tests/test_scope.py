"""Tests for core.scope — strict run-scope matching (exact, CIDR, subdomain, URLs)."""

import pytest

from core.scope import get_run_scope, normalize_host, target_in_scope


class TestNormalizeHost:
    def test_bare_domain(self):
        assert normalize_host("example.com") == "example.com"

    def test_url_strips_scheme_and_path(self):
        assert normalize_host("https://docu.bot.nu/login.php") == "docu.bot.nu"

    def test_scheme_only(self):
        assert normalize_host("http://example.com") == "example.com"

    def test_ip_passthrough(self):
        assert normalize_host("10.0.0.5") == "10.0.0.5"

    def test_case_and_trailing_dot(self):
        assert normalize_host("API.Example.COM.") == "api.example.com"


class TestTargetInScope:
    def test_exact_ip(self):
        assert target_in_scope("10.0.0.5", ["10.0.0.5"])

    def test_ip_not_in_scope(self):
        assert not target_in_scope("10.0.0.15", ["10.0.0.5"])

    def test_ip_does_not_suffix_match(self):
        # 10.0.0.5 in scope must NOT cover 10.0.0.15
        assert not target_in_scope("10.0.0.15", ["10.0.0.5"])

    def test_cidr_covers_member(self):
        assert target_in_scope("10.0.0.99", ["10.0.0.0/24"])

    def test_cidr_excludes_outsider(self):
        assert not target_in_scope("11.0.0.99", ["10.0.0.0/24"])

    def test_domain_covers_subdomain(self):
        assert target_in_scope("api.example.com", ["example.com"])

    def test_domain_does_not_match_sibling_domain(self):
        assert not target_in_scope("evil-example.com", ["example.com"])

    def test_scope_url_covers_bare_host(self):
        assert target_in_scope("example.com", ["https://example.com/login"])

    def test_target_url_against_bare_scope(self):
        assert target_in_scope("https://example.com/login", ["example.com"])

    def test_empty_scope_matches_nothing(self):
        assert not target_in_scope("example.com", [])

    def test_blank_target_matches_nothing(self):
        assert not target_in_scope("", ["example.com"])


class TestGetRunScope:
    def test_targets_and_scope_file_merged(self, tmp_path):
        from core.config import FrameworkConfig

        sf = tmp_path / "scope.txt"
        sf.write_text("# comment\n10.0.0.0/24\napi.example.com\n")
        cfg = FrameworkConfig()
        cfg.target.targets = ["example.com"]
        cfg.target.scope_file = str(sf)
        scope = get_run_scope(cfg)
        assert "example.com" in scope
        assert "10.0.0.0/24" in scope
        assert "api.example.com" in scope

    def test_missing_scope_file_ignored(self):
        from core.config import FrameworkConfig

        cfg = FrameworkConfig()
        cfg.target.scope_file = "/nonexistent/scope.txt"
        assert get_run_scope(cfg) == []

    def test_no_scope_is_empty(self):
        from core.config import FrameworkConfig

        assert get_run_scope(FrameworkConfig()) == []