"""Phase: searchsploit enrichment — correlates CVEs with local Exploit-DB entries.

Downloads proof-of-concept (PoC) code to a staging directory for operator review.
"""

import logging
import subprocess
from pathlib import Path
from typing import Optional

from core.config import FrameworkConfig, PhaseConfig
from core.knowledge_base import KnowledgeBase, Finding, ExploitLog

log = logging.getLogger(__name__)


class searchsploit_enrichment:
    """Correlate identified CVEs with local Exploit-DB data."""

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store, prior_findings, prior_exploit_logs):
        self.config = config
        self.kb = kb; self.cred_store = cred_store
        self.prior_findings = prior_findings
        self.prior_exploit_logs = prior_exploit_logs
        phase_opts = config.phases.get("searchsploit_enrichment", PhaseConfig()).options
        self.staging_dir = Path(phase_opts.get("staging_dir", "./exploit_staging"))
        self.staging_dir.mkdir(parents=True, exist_ok=True)

    # --------------------------------------------------------------- #
    # Phase lifecycle (engine convention)
    # --------------------------------------------------------------- #

    def build_task_list(self) -> list[dict]:
        """Yield one task per CVE found in prior findings."""
        tasks = []
        for f in self.prior_findings:
            cve_id = ((f.metadata or {}).get("cve_id") or "").strip().upper()
            if not cve_id or not cve_id.startswith("CVE-"):
                continue
            tasks.append({"action": "fetch_exploit", "cve_id": cve_id, "target": f.target})
        return tasks

    def execute_task(self, task: dict) -> Optional[dict]:
        """Download PoC for a single CVE."""
        if task["action"] != "fetch_exploit":
            return None
        result = self._fetch_exploit(task["cve_id"])
        status = "downloaded" if result else "not_found"
        return {"cve_id": task["cve_id"], "status": status, "local_path": result}

    # --------------------------------------------------------------- #
    # Internal helpers
    # --------------------------------------------------------------- #

    def _fetch_exploit(self, cve_id: str) -> Optional[str]:
        """Run searchsploit to download the exploit PoC locally. Returns path or None."""
        try:
            check = subprocess.run(["which", "searchsploit"], capture_output=True)
            if check.returncode != 0:
                log.warning("searchsploit not found — exploit enrichment skipped.")
                return None

            output = subprocess.run(
                ["searchsploit", cve_id, "-w"],
                capture_output=True, text=True, timeout=10,
            ).stdout

            if not output.strip():
                log.debug("No exploits found for %s", cve_id)
                return None

            exploit_path = output.strip().split("\n")[0]
            dest_filename = f"{cve_id}_exploit"
            final_dest = self.staging_dir / dest_filename

            # Use searchsploit -m to copy PoC, then we overwrite with the exact path
            subprocess.run(
                ["searchsploit", "-m", cve_id],
                capture_output=True, timeout=15,
            )

            # searchsploit -m creates a directory like <cve_id>/ under Exploit-DB; copy the first file
            import glob as _glob
            matches = _glob.glob(str(self.staging_dir / f"{cve_id}_exploit" + "*"))
            if matches:
                return matches[0]

            log.debug("searchsploit -m did not produce output for %s", cve_id)
            return None

        except Exception as exc:
            log.error("Error fetching exploit %s: %s", cve_id, exc)
            return None
