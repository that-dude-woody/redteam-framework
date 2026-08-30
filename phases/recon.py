"""Phase 1: Reconnaissance (Recon & Discovery).
Automated subdomain enumeration, port scanning, service fingerprinting,
and MassDNS validation to feed the Knowledge Base.
"""
import subprocess
import json
import os
import logging
from typing import List, Dict, Any
from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase

log = logging.getLogger(__name__)

from core.credential_store import CredentialStore


class recon:
    """Automated Reconnaissance Phase."""

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store: CredentialStore, prior_findings, prior_exploit_logs):
        self.config = config
        self.kb = kb
        self.cred_store = cred_store
        self.prior_findings = prior_findings
        self.prior_exploit_logs = prior_exploit_logs

    def build_task_list(self) -> List[Dict[str, Any]]:
        # Strict scope: recon scans ONLY the operator-supplied targets. The
        # shared KB holds data from previous campaigns, so get_discovered_targets()
        # must not be used to source a run's recon surface.
        from core.scope import normalize_host
        targets = []
        seen = set()
        for raw in getattr(self.config.target, "targets", []) or []:
            host = normalize_host(raw)
            if host and host not in seen:
                seen.add(host)
                targets.append(host)

        if not targets:
            log.warning("No configured targets to run recon on.")
            return []

        tasks = []
        for target in targets:
            tasks.append({
                "target": target,
                "type": "recon",
                "config": {
                    "subdomain_tools": ["amass", "subfinder"],
                    "massdns_validation": True,
                    "port_scan_tools": ["masscan", "nmap"]
                }
            })
        return tasks

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        target = task["target"]
        config_data = task.get("config", {})
        log.info(f"Starting Recon for {target}...")

        # 1. Subdomain Enumeration
        subdomains = self._run_subdomain_enumeration(target, config_data.get("subdomain_tools", []))
        
        # 2. MassDNS Validation Layer (Phase 3 Improvement)
        if config_data.get("massdns_validation"):
            validated_domains = self._validate_with_massdns(subdomains, target)
        else:
            validated_domains = subdomains

        if validated_domains:
            self.kb.store_target_info(target, type="domain")
            log.info(f"MassDNS validated {len(validated_domains)} subdomains for {target}")

        # 3. Port Scanning
        open_ports = self._run_port_scan(target, config_data.get("port_scan_tools", []))
        
        # 4. Service Fingerprinting
        services = self._parse_nmap_xml(target)
        self.kb.store_target_info(target, ports=open_ports, services=services)

        return {
            "status": "completed", 
            "subdomains_discovered": len(validated_domains),
            "open_ports_found": len(open_ports)
        }

    def _run_command(self, cmd, timeout=120):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return {"success": True, "output": proc.stdout + proc.stderr}
        except Exception as e:
            log.error(f"Command error: {e}")
            return {"success": False, "output": str(e)}

    def _run_subdomain_enumeration(self, target: str, tools: List[str]) -> List[str]:
        subdomains = set()
        if "amass" in tools:
            amass_out = f"/tmp/amass_{target.replace('.', '_')}_out.json"
            self._run_command(["amass", "enum", "-passive", "-d", target, "-json", amass_out])
            if os.path.isfile(amass_out):
                # amass writes verbose JSON output; keep stdout minimal (@ -passive)
                try:
                    with open(amass_out) as fh:
                        for line in fh:
                            try:
                                data = json.loads(line)
                                name = data.get("name", "")
                                if name:
                                    subdomains.add(name)
                            except json.JSONDecodeError:
                                continue
                except OSError:
                    pass

        if "subfinder" in tools:
            result = self._run_command(["subfinder", "-d", target, "-silent", "-json"])
            if result["success"]:
                for line in result["output"].strip().split('\n'):
                    try:
                        data = json.loads(line)
                        subdomains.add(data.get('subdomain', ''))
                    except json.JSONDecodeError: pass
        
        return list(subdomains)

    def _validate_with_massdns(self, domains: List[str], target: str) -> List[str]:
        """MassDNS validation layer (Tier 1 Improvement)"""
        if not domains: return []
        
        safe = target.replace("/", "_").replace(".", "_")
        tmp_file = f"/tmp/massdns_input_{safe}.txt"
        out_file = f"/tmp/massdns_output_{safe}.txt"
        with open(tmp_file, "w") as f:
            f.write("\n".join(domains))
            
        cmd = [
            "massdns", "-r", "/usr/share/dns/resolvers.txt", 
            "-t", "A", "-o", "S", tmp_file, out_file
        ]
        self._run_command(cmd)
        
        validated = []
        try:
            with open(out_file, "r") as f:
                for line in f.readlines():
                    # MassDNS status 'S' means success
                    parts = line.split()
                    if len(parts) >= 5 and parts[3] == "A":
                        validated.append(parts[0].strip("."))
        except FileNotFoundError:
            pass
            
        return validated

    def _run_port_scan(self, target: str, tools: List[str]) -> Dict[int, str]:
        open_ports = {}
        safe = target.replace("/", "_").replace(".", "_")
        masscan_out = f"/tmp/masscan_result_{safe}.json"
        nmap_out = f"/tmp/nmap_result_{safe}.xml"
        
        if "masscan" in tools:
            self._run_command([
                "masscan", f"{target}", "-p1-65535", "--rate=1000", 
                "-oJ", masscan_out
            ])
            try:
                with open(masscan_out) as f:
                    data = json.load(f)
                    for item in data:
                        port = int(item.get('port', 0))
                        if port not in open_ports:
                            open_ports[port] = "open"
            except FileNotFoundError: pass

        if "nmap" in tools:
            # Standard Nmap to fingerprint services on found ports
            ports_str = ",".join([str(p) for p in list(open_ports.keys())[:100]])
            if not ports_str: ports_str = "1-1000"
            
            self._run_command([
                "nmap", f"-p{ports_str}", "-sV", "-sC", "--osscan-guess", 
                "-oX", nmap_out, target
            ])
            
        return open_ports

    def _parse_nmap_xml(self, target: str) -> List[Dict[str, Any]]:
        import xml.etree.ElementTree as ET
        services = []
        try:
            safe = target.replace("/", "_").replace(".", "_")
            tree = ET.parse(f'/tmp/nmap_result_{safe}.xml')
            root = tree.getroot()
            for host in root.findall('host'):
                addr = host.find('address').get('addr', target)
                for port in host.findall('.//port'):
                    proto = port.get('protocol')
                    port_num = int(port.get('portid'))
                    state = port.find('state').get('state')
                    if state == 'open':
                        service_elem = port.find('service')
                        s_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                        services.append({
                            "target": target, "ip": addr, "port": port_num, 
                            "protocol": proto, "name": s_name, "status": state
                        })
        except Exception: pass
        return services
