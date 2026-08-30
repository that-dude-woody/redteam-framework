"""Tests for core.tool_executor — ToolResult, resolve_binary, run timeout handling."""
import subprocess
import pytest
from unittest.mock import patch, MagicMock

from core.tool_executor import ToolExecutor, ToolResult


class TestToolResult:
    def test_defaults(self):
        r = ToolResult(success=True)
        assert r.success is True
        assert r.stdout == ""
        assert r.stderr == ""
        assert r.return_code == -1
        assert r.parsed is None

    def test_str_representation(self):
        r = ToolResult(success=True, stdout="hello")
        assert "hello" in str(r)  # str() includes fields via dataclass


class TestToolExecutor:
    @pytest.fixture()
    def executor(self):
        return ToolExecutor(default_timeout=300)

    # resolve_binary
    def test_resolve_binary_true(self, executor):
        """which 'sh' always exists on sane systems."""
        path = executor.resolve_binary("sh")
        assert path is not None

    def test_resolve_binary_false(self, executor):
        path = executor.resolve_binary("nonexistent_tool_xyz_42")
        assert path is None

    def test_resolve_binary_bin_dir_priority(self):
        import tempfile, os, stat  # noqa: E402

        tmpdir = tempfile.mkdtemp()
        tool_path = os.path.join(tmpdir, "mytesttool")
        with open(tool_path, "w") as f:
            f.write("#!/bin/sh\necho hi\n")
        st = os.stat(tool_path)
        os.chmod(tool_path, st.st_mode | stat.S_IEXEC)

        executor = ToolExecutor(bin_dir=tmpdir)
        path = executor.resolve_binary("mytesttool")
        assert path is not None
        assert "mytesttool" in path

        # cleanup
        os.remove(tool_path)
        os.rmdir(tmpdir)

    # run — simulated via subprocess mock
    def test_run_binary_not_found(self, executor):
        result = executor.run("nonexistent_xyz_42", ["arg1"])
        assert result.success is False
        assert "Binary not found" in result.stderr

    def test_run_success(self):
        proc_mock = MagicMock()
        proc_mock.returncode = 0
        proc_mock.stdout = '["ok"]'
        proc_mock.stderr = ""
        exec_mock = MagicMock(return_value=proc_mock)
        executor = ToolExecutor(default_timeout=300)
        executor.resolve_binary = MagicMock(return_value="/bin/sh")
        with patch("core.tool_executor.subprocess.run", exec_mock):
            result = executor.run("sh", ["-c", "true"], parse_json=True)
        assert result.success is True
        assert result.parsed == ["ok"]

    def test_run_failure(self):
        exec_mock = MagicMock(return_value=MagicMock(
            returncode=1, stdout="", stderr="error!"))
        executor = ToolExecutor(default_timeout=300)
        executor.resolve_binary = MagicMock(return_value="/bin/sh")
        with patch("core.tool_executor.subprocess.run", exec_mock):
            result = executor.run("sh", ["-c", "false"])
        assert result.success is False
        assert result.return_code == 1

    def test_run_timeout(self):
        import subprocess as _subp  # noqa: E402
        exec_mock = MagicMock(side_effect=_subp.TimeoutExpired("sh", 5))
        executor = ToolExecutor(default_timeout=300)
        executor.resolve_binary = MagicMock(return_value="/bin/sh")
        with patch("core.tool_executor.subprocess.run", exec_mock):
            result = executor.run("sh", ["-c", "sleep 1"], timeout=5)
        assert result.success is False
        assert ("timed out" in result.stderr.lower() or "TimeoutExpired" in result.stderr)

    def test_run_json_parsing_fallback(self):
        exec_mock = MagicMock(return_value=MagicMock(
            returncode=0, stdout='{"a":1}\n{"b":2}\n', stderr=""))
        executor = ToolExecutor(default_timeout=300)
        executor.resolve_binary = MagicMock(return_value="/bin/sh")
        with patch("core.tool_executor.subprocess.run", exec_mock):
            result = executor.run("sh", ["-c", "echo"], parse_json=True)
        assert isinstance(result.parsed, list)
        assert len(result.parsed) == 2
        assert result.parsed[0]["a"] == 1

    def test_run_capture_stderr_false(self):
        exec_mock = MagicMock(return_value=MagicMock(
            returncode=0, stdout="out", stderr="err"))
        executor = ToolExecutor(default_timeout=300)
        executor.resolve_binary = MagicMock(return_value="/bin/sh")
        with patch("core.tool_executor.subprocess.run", exec_mock):
            result = executor.run("sh", [], capture_stderr=False)
        assert result.success is True
        assert result.stderr == ""

    # extract_hosts
    def test_extract_hosts_ip(self, executor):
        hosts = executor.extract_hosts("Scanned 192.168.1.1 and 10.0.0.2 and 172.16.0.3")
        assert set(hosts) >= {"192.168.1.1", "10.0.0.2", "172.16.0.3"}

    def test_extract_hosts_domain(self, executor):
        hosts = executor.extract_hosts("Found example.com and sub.example.org")
        assert set(hosts) >= {"example.com", "sub.example.org"}

    def test_extract_hosts_mixed(self, executor):
        text = "IP: 10.0.0.1 DNS: foo.bar.com"
        hosts = executor.extract_hosts(text)
        assert len(hosts) == 2
        assert "10.0.0.1" in hosts
        assert "foo.bar.com" in hosts

    def test_extract_hosts_empty(self, executor):
        hosts = executor.extract_hosts("")
        assert hosts == []
