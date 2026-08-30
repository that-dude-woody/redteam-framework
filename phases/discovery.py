"""Discovery Phase - Production Implementation (Expanded Toolset)."""
import logging, re, xml.etree.ElementTree as ET
from urllib.parse import urlparse
from core.config import FrameworkConfig
from core.knowledge_base import KnowledgeBase, Finding
from core.tool_executor import ToolExecutor

log = logging.getLogger(__name__)

class discovery:
    TOOLS_REGISTRY = {
        "masscan":     {"profiles": ["tcp/1-65535", "tcp/1-1000"]},
        "nmap_fast":   {"args": ["-sV", "--top-ports", "100", "-oX", "/tmp/nmap_{target}.xml", "{target}"]},
        "nmap_deep":   {"args": ["-sS", "-sV", "-T4", "-A", "--top-ports", "1000", "-oX", "/tmp/nmap_deep_{target}.xml", "{target}"]},
        "httpx":       {"args": ["{targets_file}", "-json", "-silent", "-follow-host-redirects"]},
        "gobuster_dir":{"args": ["dir", "-u", "http://{target}", "-w", "/usr/share/wordlists/dirb/common.txt", "--no-error", "-q"]},
        "rustscan":    {"args": ["-a", "{target}", "-t", "5000"]},
    }

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase, cred_store, prior_findings, prior_exploit_logs):
        self.config = config; self.kb = kb; self.cred_store = cred_store
        self.prior_findings = prior_findings; self.prior_exploit_logs = prior_exploit_logs
        self.te = ToolExecutor(default_timeout=600)

    _NOISE_TLDS = {"bot.nu"}  # known noise TLDs — operator targets are never filtered
    _DNS_INFRA_PATTERNS = [
        re.compile(r".*-servers\.net$"),           # Verisign GTLD servers (a.gtld-servers.net)
        re.compile(r".*\.afilias-nst\.info$"),     # Afilias naming authority
        re.compile(r"^ns\d+\.", re.I),             # ns1.example.com, ns2.example.com
        re.compile(r"^(dns|mx|mail)[0-9]*\.", re.I), # dns1.*, mx.*, mail*.*
        re.compile(r".*\.in-addr\.arpa$"),          # Reverse DNS lookups
        re.compile(r"^\d+\.\d+\.\d+\.\d+$"),   # Bare IP addresses
    ]

    @classmethod
    def _is_dns_infra(cls, host: str) -> bool:
        """Return True if host looks like DNS infrastructure rather than an app target."""
        for pat in cls._DNS_INFRA_PATTERNS:
            if pat.match(host): return True
        # Exclude known noise TLDs
        for tld in cls._NOISE_TLDS:
            if host.endswith(tld): return True
        return False
    _KNOWN_PARENTS = None  # lazily populated set of operator-defined targets
    
    def _resolve_targets(self) -> list[str]:
        """Extract unique target hosts from prior findings and config targets.
        
        Strategy (most specific → broadest):
          1. dns_* / host_* categories — direct subdomain discoveries
          2. osint_* categories — strip scheme/path, deduplicate to bare hostname
          3. Config-defined targets themselves are always included
        Evidence text is NOT used for host extraction (produces DNS servers,
        filenames, etc. that swamp the scan queue).
        """
        hosts = set()
        # Always include operator-configured targets
        for t in getattr(self.config.target, 'targets', []):
            parsed = urlparse(t)
            h = (parsed.hostname or t.strip("/")).lower().strip(".")
            if h: hosts.add(h)
        
        for f in self.prior_findings:
            raw = f.target.strip()
            # Direct DNS/host category — trust it
            if "dns" in f.category.lower() or "host" in f.category.lower():
                hosts.add(raw.lower().strip("."))
            # OSINT findings often store a full URL as target
            elif f.category.startswith("osint_"):
                parsed = urlparse(raw)
                hostname = (parsed.hostname or parsed.path.strip("/")).lower()
                if hostname and not hostname.replace(".", "").isdigit():
                    hosts.add(hostname.strip("."))
        
        # Filter out obviously-noisy entries: non-FQDN strings, IPs-only, noise domains
        valid = set()
        # Allow both bare domain.tld (google.com) and subdomains (www.google.com)
        re_fqdn = re.compile(r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,}|(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.[a-zA-Z]{2,})$')
        for h in hosts:
            if re_fqdn.match(h) and not self._is_dns_infra(h):
                valid.add(h)
        
        log.info(f"Discovery resolved {len(valid)} targets (filtered from {len(hosts)} raw)")
        return sorted(valid)

    def build_task_list(self) -> list[dict]:
        tasks = []

        # httpx: run once against known HTTP(S) endpoints (deduped by target).
        # Independent of _resolve_targets() because its candidates are bare-IP
        # open_port findings that the FQDN filter deliberately drops.
        if self.te.resolve_binary("httpx"):
            web_hosts = {f.target for f in self.prior_findings
                         if f.category == "open_port"
                         and f.metadata.get("port") in (80, 443, 8080, 8443)}
            if web_hosts:
                tasks.append({"action": "httpx_fingerprint", "targets": sorted(web_hosts)})

        targets = self._resolve_targets()
        if not targets:
            return tasks

        # Port scanners — use reasonable defaults, not full 65535
        available_scanners = []
        if self.te.resolve_binary("masscan"):   available_scanners.append(("masscan", ["-p", "1-1000", "-rA", "{target}", "--rate=1000"]))
        if self.te.resolve_binary("rustscan"):  available_scanners.append(("rustscan", ["-a", "{target}", "-t", "5000", "-b", "Top1000"]))
        
        for name, tmpl in available_scanners:
            for t in targets: tasks.append({"action": f"port_scan_{name}", "target": t, "args": [a.replace("{target}",t) for a in tmpl]})
        
        if self.te.resolve_binary("nmap"):
            for t in targets:
                tasks.append({"action": "nmap_version",  "target": t, "profile": "fast"})
                # deep scan is optional — skip by default to save time
                # tasks.append({"action": "nmap_version",  "target": t, "profile": "deep"})

        return tasks

    def execute_task(self, task: dict):
        if task["action"].startswith("port_scan_"): self._run_generic_portscan(task)
        elif task["action"] == "nmap_version":     self._run_nmap(task)
        elif task["action"] == "httpx_fingerprint": self._run_httpx(task)

    def _run_generic_portscan(self, task: dict):
        scanner = task["action"].replace("port_scan_", "")
        res = self.te.run(scanner, task["args"], timeout=600)
        if not res.success or not res.stdout: return
        for line in res.stdout.split("\n"):
            m = re.search(r"(\d+)\+?\s*(open|filtered)?", line)
            if m: 
                port_num = int(m.group(1))
                state = m.group(2) or "unknown"
                self.kb.add_finding(Finding(phase="discovery", target=task["target"], category="open_port", severity="info", title=f"Open port {port_num}/{state}", description=f"Port {port_num} detected as {state} on {task['target']}", metadata={"port": port_num, "state": state, "source": scanner}))

    def _run_nmap(self, task: dict):
        profile = {
            "fast": ["-sV", "--top-ports", "100"],
            "deep": ["-sS", "-sV", "-T4", "-A", "--top-ports", "1000"]
        }.get(task["profile"])
        if not profile: return
        out_xml = f"/tmp/nmap_{task['profile']}_{task['target'].replace('.','_')}.xml"
        cmd = ["nmap", *profile, "-oX", out_xml, task["target"]]
        res = self.te.run("nmap", cmd, timeout=900)
        if not res.success: return
        try:
            tree = ET.parse(out_xml); root = tree.getroot()
            for host in root.findall(".//host"):
                status = host.find("status"); st = status.get("state") if status is not None else "unknown"
                address = host.find("address"); ip = address.get("addr","") if address is not None else task["target"]
                for port in host.findall(".//port"):
                    pnum = port.get("portid",""); state = port.find("state"); ps = state.get("state","unknown") if state is not None else "unknown"
                    svc = port.find("service"); sn = svc.get("name","") if svc is not None else ""
                    ver = svc.get("product","") + (" "+svc.get("version","")) if svc is not None else ""
                    self.kb.add_finding(Finding(phase="discovery", target=ip, category="service", severity="info", title=f"Service {sn} on port {pnum}", description=f"Port {pnum}/{ps} [{sn} {ver}]", metadata={"port": int(pnum), "state": ps, "service_name": sn, "version_info": ver.strip(), "scanner": f"nmap_{task['profile']}"}))
        except Exception as e: log.error(f"Nmap XML parse failed: {e}")

    def _run_httpx(self, task: dict):
        """Fingerprint discovered HTTP(S) endpoints once, deduped against known web_app findings."""
        if not self.te.resolve_binary("httpx"): return
        candidates = set(task.get("targets") or [])
        # Live merge: pick up hosts scanned earlier in this phase
        for f in self.kb.get_all_findings():
            if f.category == "open_port" and f.metadata.get("port") in (80, 443, 8080, 8443):
                candidates.add(f.target)
        for t in getattr(self.config.target, "targets", []):
            host = urlparse(t).hostname or t.strip("/")
            if host: candidates.add(host.lower().strip("."))
        if not candidates: return

        host_file = "/tmp/httpx_hosts.txt"
        with open(host_file, "w") as fh: fh.write("\n".join(sorted(candidates)))
        res = self.te.run("httpx", [host_file, "-json", "-silent"], parse_json=True)
        if not (res.success and isinstance(res.parsed, list)): return

        known = {f.target for f in self.kb.get_all_findings() if f.category == "web_app"}
        for entry in res.parsed:
            url = entry.get("url", ""); status = entry.get("status_code", 0)
            if not url or url in known: continue
            known.add(url)
            techs = ", ".join(entry.get("tech", [])) if isinstance(entry.get("tech"), list) else entry.get("tech", "")
            self.kb.add_finding(Finding(
                phase="discovery", target=url, category="web_app", severity="info",
                title=f"Web app {url} (HTTP {status})",
                description=f"HTTP {status}",
                metadata={"source": "httpx", "status_code": status, "technologies": techs}))

    def get_available_tools(self) -> list[str]:
        avail = []
        for name in self.TOOLS_REGISTRY: avail.append(name if (self.te.resolve_binary("nmap") if "nmap" in name else self.te.resolve_binary(name)) else None)
        return sorted(set(filter(None, avail)))
