"""Directory / file fuzzing phase using ffuf — alternative to gobuster dir module."""
import logging, subprocess
from typing import List, Dict, Any
from core.config import FrameworkConfig
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase, Finding
from core.wordlists import resolve

log = logging.getLogger(__name__)


class ffuf:
    """Directory/file fuzzing with ffuf (Fuzz Faster U Fool)."""

    TOOLS_REGISTRY = {"ffuf": {}}

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store: CredentialStore, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb
        self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs

    # ------------------------------------------------------------------ #
    # Task list builder
    # ------------------------------------------------------------------ #

    def build_task_list(self) -> list[dict]:
        tasks = []
        if not _resolve_binary("ffuf"):
            log.info("ffuf not found — skipping ffuf phase")
            return tasks

        known_hosts: set[str] = set()
        for f in self.prior_findings:
            if f.category in ("web_app", "open_port", "service", "vhost_found"):
                known_hosts.add(f.target)

        for t in getattr(self.config.target, 'targets', []):
            known_hosts.add(t)

        # Use any discovered vhosts as fuzz targets
        for host in sorted(known_hosts):
            base_url = host
            if not base_url.startswith("http"):
                base_url = f"http://{base_url}"
            tasks.append({"action": "dir_fuzz", "url": base_url})

        return tasks

    def execute_task(self, task: dict):
        if task["action"] == "dir_fuzz":
            self._run_dir_fuzz(task)

    # ------------------------------------------------------------------ #
    # dir-fuzz logic
    # ------------------------------------------------------------------ #

    def _run_dir_fuzz(self, task: dict):
        url = task["url"]
        wordlist = resolve("web")

        cmd = [
            "ffuf", "-u", f"{url}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,202,204,301,302,307,401,403",
            "-c",
        ]

        res = self._run(cmd)
        if res.returncode != 0:
            return

        for line in res.stdout.strip().splitlines():
            # ffuf outputs lines like:
            #   [200]    123     4567    12345.6    http://target/FUZZVAL
            parts = line.split()
            if len(parts) < 5 or not parts[0].startswith("["):
                continue
            try:
                status_code = int(parts[0].strip("[]"))
            except ValueError:
                continue

            # URL is always last field in ffuf output
            fuzzed_url = parts[-1] if len(parts) >= 2 else url

            severity = "low" if status_code in (200, 301, 302, 307) else "medium" if status_code == 403 else "high"
            self.kb.add_finding(
                Finding(phase="dir_fuzz", target=url.split("://")[-1].split("/")[0] if "://" in url else url,
                        category="directory_discovery", severity=severity,
                        title=f"[ffuf] {fuzzed_url}",
                        description=f"Status {status_code} on {fuzzed_url}",
                        metadata={"source": "ffuf", "status_code": status_code, "url": fuzzed_url}),
            )

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
