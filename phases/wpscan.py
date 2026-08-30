"""WordPress detection and exploitation phase using WPScan."""
import logging, subprocess
from typing import List, Dict, Any
from core.config import FrameworkConfig
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase, Finding

log = logging.getLogger(__name__)


class wpscan:
    """WordPress detection / plugin enumeration via WPScan."""

    TOOLS_REGISTRY = {"wpscan": {}}

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store: CredentialStore, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb
        self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs

    # ------------------------------------------------------------------ #
    # Task list builder
    # ------------------------------------------------------------------ #

    def build_task_list(self) -> list[dict]:
        tasks = []
        if not _resolve_binary("wpscan"):
            log.info("WPScan not found — skipping WordPress phase")
            return tasks

        known_urls: set[str] = set()
        for f in self.prior_findings:
            if f.category == "web_app":
                url = f.target
                if not url.startswith("http"):
                    url = f"http://{url}"
                known_urls.add(url)

        for url in sorted(known_urls):
            tasks.append({"action": "detect_wpsite", "url": url})

        return tasks

    def execute_task(self, task: dict):
        if task["action"] == "detect_wpsite":
            self._run_detect(task)

    # ------------------------------------------------------------------ #
    # Detection logic
    # ------------------------------------------------------------------ #

    def _run_detect(self, task: dict):
        url = task["url"]
        cmd = ["wpscan", "--url", url, "--random-user-agent", "--ignore-main-404", "-f"]
        res = self._run(cmd)
        if not res.success or "WordPress" not in res.stdout:
            return

        version = self._extract_field(res.stdout, "Version:")
        info_url = []
        in_plugins = False
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if "Plugins Installed:" in stripped:
                in_plugins = True
                continue
            if in_plugins and stripped.startswith("[+]"):
                info_url.append(stripped)
            elif in_plugins and not stripped.startswith("[+"):
                in_plugins = False

        # WordPress detected as a finding
        self.kb.add_finding(
            Finding(phase="wpscan", target=url, category="cms_detected", severity="info",
                    title=f"WordPress site detected — {version or 'unknown version'}",
                    description=f"WPScan identified WordPress at {url}",
                    metadata={"source": "wpscan", "wordpress_version": version}),
        )

        # Each plugin as its own finding (potential vuln surface)
        if info_url:
            self.kb.add_finding(
                Finding(phase="wpscan", target=url, category="cms_detected", severity="low",
                        title=f"WordPress plugins detected ({len(info_url)} found)",
                        description="\n".join(f"  - {p.strip()}" for p in info_url),
                        metadata={"source": "wpscan"}),
            )

    @staticmethod
    def _extract_field(text: str, field_name: str) -> str:
        for line in text.splitlines():
            if field_name in line:
                return line.split(field_name)[-1].strip()
        return ""

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, OSError):
            return subprocess.CompletedProcess(args=cmd, returncode=127, stdout="", stderr="binary not found")

    def get_available_tools(self) -> list[str]:
        return [n for n in self.TOOLS_REGISTRY if _resolve_binary(n)]


def _resolve_binary(name: str) -> bool:
    try:
        result = subprocess.run(["which", name], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False
