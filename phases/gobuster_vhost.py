"""VHost Discovery Phase - Gobuster vhost/fuzz modules."""
import logging, subprocess, json
from typing import List, Dict, Any
from core.config import FrameworkConfig
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase, Finding
from core.wordlists import resolve

log = logging.getLogger(__name__)


class gobuster_vhost:
    """Virtual host discovery using Gobuster's vhost and directory-fuzz modules."""

    TOOLS_REGISTRY = {
        "gobuster": {"modules": ["vhost", "dir"]},
    }

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store: CredentialStore, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb
        self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs

    # ------------------------------------------------------------------ #
    # Task list builder
    # ------------------------------------------------------------------ #

    def build_task_list(self) -> list[dict]:
        tasks = []
        if not _resolve_binary("gobuster"):
            log.info("Gobuster not found — skipping vhost/fuzz phase")
            return tasks

        # Collect unique hostnames from recon + discovery findings
        known_hosts: set[str] = set()
        for f in self.prior_findings:
            if f.category in ("web_app", "open_port", "service"):
                known_hosts.add(f.target)

        # Also pull IPs that resolved to something during recon
        for t in getattr(self.config.target, 'targets', []):
            known_hosts.add(t)

        for host in sorted(known_hosts):
            tasks.append({"action": "vhost_discovery", "target": host})
            tasks.append({"action": "dir_fuzz", "target": host})

        return tasks

    def execute_task(self, task: dict):
        if task["action"] == "vhost_discovery":
            self._run_vhost(task)
        elif task["action"] == "dir_fuzz":
            self._run_dir_fuzz(task)

    # ------------------------------------------------------------------ #
    # vhost module
    # ------------------------------------------------------------------ #

    def _run_vhost(self, task: dict):
        target = task["target"]
        wordlist = resolve("vhosts")
        res = self._exec_gobuster(["vhost", "-u", target, "-w", wordlist, "-s", "200,301,302,403,426,500"])

        if res.returncode != 0 or not res.stdout.strip():
            log.info("Gobuster vhost returned nothing for %s", target)
            return

        for line in res.stdout.strip().splitlines():
            # Gobuster outputs: 2026/08/18 10:00:00 [!] example.com:80 (Status: 301) [Size: 123]
            if "Status:" not in line:
                continue
            parts = line.split()
            status_code = None
            hostname = target
            for i, token in enumerate(parts):
                if token.startswith("[!"):
                    # Extract hostname from "[!] host:port"
                    raw = token.strip("[]!")
                    hostname = raw.rsplit(":", 1)[0] if ":" in raw else raw
                if token == "Status:" and i + 1 < len(parts):
                    try:
                        status_code = int(token.replace("Status:", "").strip(",)"))
                    except ValueError:
                        pass
            if not status_code:
                continue

            severity = "low" if status_code in (200, 301, 302) else "medium" if status_code == 403 else "high"
            self.kb.add_finding(
                Finding(phase="vhost_discovery", target=target, category="vhost_found",
                        severity=severity, title=f"[Gobuster-vhost] VHost: {hostname}",
                        description=f"Status {status_code} on vhost {hostname} at target {target}",
                        metadata={"source": "gobuster_vhost", "vhost": hostname, "status_code": status_code}),
            )

    # ------------------------------------------------------------------ #
    # dir-fuzz module
    # ------------------------------------------------------------------ #

    def _run_dir_fuzz(self, task: dict):
        target = task["target"]
        wordlist = resolve("web")
        res = self._exec_gobuster(["dir", "-u", target, "-w", wordlist, "-s", "200,301,302,403,426,500", "-e"])

        if res.returncode != 0 or not res.stdout.strip():
            return

        for line in res.stdout.strip().splitlines():
            if "Status:" not in line:
                continue
            parts = line.split()
            status_code = None
            url = target
            for i, token in enumerate(parts):
                if token == "Status:" and i + 1 < len(parts):
                    try:
                        status_code = int(token.replace("Status:", "").strip(",)"))
                    except ValueError:
                        pass
                if token.endswith("/"):
                    url = token.rstrip("/")

            if not status_code:
                continue

            severity = "low" if status_code in (200, 301, 302) else "medium"
            self.kb.add_finding(
                Finding(phase="vhost_discovery", target=target, category="directory_discovery",
                        severity=severity, title=f"[Gobuster-dir] {url}",
                        description=f"Status {status_code} on {url}",
                        metadata={"source": "gobuster_dir", "path": url, "status_code": status_code}),
            )

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _exec_gobuster(self, args: list[str]) -> subprocess.CompletedProcess:
        cmd = ["gobuster"] + args
        return self._run(cmd)

    @staticmethod
    def _run(cmd: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (FileNotFoundError, OSError):
            return subprocess.CompletedProcess(args=cmd, returncode=127, stdout="", stderr="binary not found")

    def get_available_tools(self) -> list[str]:
        return [n for n in self.TOOLS_REGISTRY if _resolve_binary(n.split("_")[0])]


# ── bare helpers (avoid import loops) ───────────────────────────────

def _resolve_binary(name: str) -> bool:
    try:
        result = subprocess.run(["which", name], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False
