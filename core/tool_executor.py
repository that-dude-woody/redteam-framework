"""
Standardized external tool execution layer.

Wraps subprocess calls with safety guarantees: timeouts, output sanitization,
JSON parsing helpers, and graceful failure isolation so one bad tool doesn't
crash the entire framework engine.
"""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Captures the result of a tool execution."""
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    parsed: Optional[dict] = None  # Pre-parsed JSON if applicable


class ToolExecutor:
    """Manages the invocation of external red team utilities."""

    def __init__(self, bin_dir: Optional[str] = None, default_timeout: int = 300):
        self.bin_dir = Path(bin_dir) if bin_dir else None
        self.default_timeout = default_timeout
        self._cache_tools()

    def _cache_tools(self):
        """Pre-check available tools to avoid repeated `shutil.which` lookups."""
        self._binary_cache: dict[str, Optional[str]] = {}

    def resolve_binary(self, name: str) -> Optional[str]:
        """Find a tool binary by name. Checks local bin_dir first, then system PATH."""
        if name in self._binary_cache:
            return self._binary_cache[name]
        path: Optional[str] = None
        if self.bin_dir and (self.bin_dir / name).exists():
            path = str(self.bin_dir / name)
        else:
            path = shutil.which(name)
        self._binary_cache[name] = path
        return path

    def run(
        self, 
        tool_name: str, 
        args: list[str], 
        timeout: Optional[int] = None,
        parse_json: bool = False,
        capture_stderr: bool = True,
    ) -> ToolResult:
        """
        Execute a tool safely.
        
        Args:
            tool_name: Binary name or full path (e.g., "nmap", "/opt/amass")
            args: Command-line arguments list
            timeout: Seconds before forcing termination (falls back to default_timeout)
            parse_json: If True, attempts to parse stdout as JSON lines/arrays
            capture_stderr: Whether to include stderr in the result object
            
        Returns:
            ToolResult with success status, raw output, and optionally parsed data
        """
        bin_path = self.resolve_binary(tool_name) if "/" not in tool_name else tool_name
        
        if not bin_path or not Path(bin_path).exists():
            log.warning(f"Tool not found: {tool_name}")
            return ToolResult(success=False, stderr=f"Binary not found: {tool_name}")

        full_cmd = [bin_path] + args
        log.debug(f"Executing tool: {' '.join(full_cmd)}")

        try:
            proc = subprocess.run(
                full_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
                timeout=timeout or self.default_timeout,
                text=True,
                check=False
            )
            
            result = ToolResult(
                success=proc.returncode == 0,
                stdout=proc.stdout,
                stderr=proc.stderr if capture_stderr else "",
                return_code=proc.returncode,
            )

            # Parse JSON output if requested (handles both full-JSON and JSONL)
            if parse_json and result.stdout:
                try:
                    # Try strict array/object first
                    data = json.loads(result.stdout)
                except json.JSONDecodeError:
                    try:
                        # Fallback to JSON lines
                        data = [json.loads(line) for line in result.stdout.strip().split('\n') if line]
                    except Exception:
                        data = None
                result.parsed = data

            return result

        except subprocess.TimeoutExpired:
            log.warning(f"Tool timeout ({timeout or self.default_timeout}s): {' '.join(full_cmd)}")
            return ToolResult(success=False, stderr=f"Execution timed out after {timeout or self.default_timeout}s")
        except Exception as exc:
            log.error(f"Tool execution crashed: {exc}")
            return ToolResult(success=False, stderr=str(exc))

    # ------------------------------------------------------------------ #
    # Helpers for common tool outputs
    # ------------------------------------------------------------------ #

    def extract_hosts(self, output: str) -> list[str]:
        """Extract unique IPs/domains from raw tool text output."""
        import re
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        host_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        found = set()
        found.update(re.findall(ip_pattern, output))
        found.update(re.findall(host_pattern, output))
        return list(found)
