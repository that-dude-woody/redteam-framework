"""Domain mutation / alternative DNS enumeration using altdns / dnsgen."""
import logging, subprocess
from typing import List, Dict, Any
from core.config import FrameworkConfig
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase, Finding

log = logging.getLogger(__name__)


class altdns:
    """Mutate discovered hostnames to find alternative subdomains via DNS resolution."""

    TOOLS_REGISTRY = {
        "altdns": {},
        "dnsgen": {},
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
        if not (_resolve_binary("altdns") or _resolve_binary("dnsgen")):
            log.warning("Neither altdns nor dnsgen found — skipping domain mutation phase")
            return tasks

        # Gather base domains from recon findings
        base_domains: set[str] = set()
        for f in self.prior_findings:
            if f.category == "subdomain":
                domain = f.target
                # Extract base domain (last 2 parts)
                parts = domain.split(".")
                if len(parts) >= 2:
                    base_domains.add(".".join(parts[-2:]))

        for d in sorted(base_domains):
            tasks.append({"action": "mutate", "domain": d})

        return tasks

    def execute_task(self, task: dict):
        if task["action"] == "mutate":
            self._run_mutate(task)

    # ------------------------------------------------------------------ #
    # Mutation logic
    # ------------------------------------------------------------------ #

    def _run_mutate(self, task: dict):
        domain = task["domain"]

        # altdns mode: generate permutations, pipe to massdns for validation
        if _resolve_binary("altdns"):
            cmd_altdns = ["altdns", "-d", domain, "-r"]
            res_alt = self._run(cmd_altdns)
            if not res_alt.success or not res_alt.stdout.strip():
                log.info("altdns returned nothing for %s", domain)
                return

            mutations = set()
            for line in res_alt.stdout.strip().splitlines():
                line = line.strip(".")
                if line:
                    mutations.add(line)

            # Validate mutations with massdns
            if _resolve_binary("massdns") and mutations:
                tmpfile = "/tmp/altdns_input.txt"
                import os  # noqa: E402
                with open(tmpfile, "w") as fh:
                    fh.write("\n".join(mutations))

                res_dns = self._run([
                    "massdns", "-r", "/usr/share/dns/resolvers.txt",
                    "-t", "A", "-o", "S", tmpfile, "/tmp/altdns_output.txt",
                ])
                if res_dns.success:
                    try:
                        import os as _os  # noqa: E402
                        if _os.path.isfile("/tmp/altdns_output.txt"):
                            with open("/tmp/altdns_output.txt") as fh:
                                for line in fh:
                                    parts = line.split()
                                    if len(parts) >= 5 and parts[3] == "A":
                                        validated_domain = parts[0].strip(".")
                                        self.kb.add_finding(
                                            Finding(phase="altdns", target=domain, category="subdomain",
                                                    severity="info", title=f"[altdns] Mutated subdomain: {validated_domain}",
                                                    metadata={"source": "altdns", "base_domain": domain}),
                                        )
                    except Exception:
                        pass

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _run(cmd: list[str], timeout: int = 120) -> subprocess.CompletedProcess:
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
