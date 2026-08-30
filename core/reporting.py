"""
Advanced Report generation from the Knowledge Base.

Produces JSON and Markdown reports summarizing all findings, exploit logs,
and phase completion status for a given campaign. Includes executive summaries,
severity badges, and structured tables.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List

from core.config import FrameworkConfig, REPORTS_DIR
from core.knowledge_base import KnowledgeBase, Finding, ExploitLog


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")


class Reporter:
    """Generate campaign reports backed by the KB."""

    def __init__(self, config: FrameworkConfig, kb: KnowledgeBase):
        self.config = config
        self.kb = kb
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #

    def generate(self, formats: Optional[List[str]] = None):
        """Generate reports in the requested formats (json/markdown)."""
        fmts = formats or self.config.report_format
        summary = self.kb.summary()
        findings = self.kb.get_all_findings()
        logs = self.kb.get_exploit_logs()

        if "json" in fmts:
            self._write_json(summary, findings, logs)

        if "markdown" in fmts:
            self._write_markdown(summary, findings, logs)

        return {f: True for f in fmts}

    @property
    def _report_name(self) -> str:
        """Build a unique report filename from campaign + targets + timestamp."""
        ts = _timestamp().replace("Z", "")
        target_slug = "_".join(
            t.strip().replace(".", "_").replace("/", "_").replace(":", "_")[:20]
            for t in getattr(self.config.target, 'targets', ['unknown'])[:3]
        )
        return f"{self.config.campaign_id}_{target_slug}_{ts}"

    # ------------------------------------------------------------------ #
    # JSON report
    # ------------------------------------------------------------------ #

    def _write_json(self, summary, findings, logs):
        payload = {
            "campaign_id": self.config.campaign_id,
            "operator": self.config.operator_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "findings": [f.__dict__ for f in findings],
            "exploit_logs": [l.__dict__ for l in logs],
        }

        path = REPORTS_DIR / f"{self._report_name}.json"
        with open(path, "w") as fh:
            json.dump(payload, fh, indent=2)
        return path

    # ------------------------------------------------------------------ #
    # Markdown report (Advanced)
    # ------------------------------------------------------------------ #

    def _write_markdown(self, summary, findings, logs):
        lines = []
        
        # --- Header & Executive Summary ---
        lines.append(f"# 🔴 Red Team Campaign Report: {self.config.campaign_id}")
        lines.append(f"**Operator:** {self.config.operator_name}  \n**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append("")
        
        # Executive Summary Section
        total_findings = summary.get('total_findings', 0)
        critical = summary.get('findings_by_severity', {}).get('critical', 0)
        high = summary.get('findings_by_severity', {}).get('high', 0)
        medium = summary.get('findings_by_severity', {}).get('medium', 0)
        
        lines.append("## 📊 Executive Summary")
        lines.append(f"- **Total Findings:** {total_findings}")
        lines.append(f"- **Critical Risk Findings:** 🔴 {critical}")
        lines.append(f"- **High Risk Findings:** 🟠 {high}")
        lines.append(f"- **Medium/Low Findings:** 🟡 {medium + summary.get('findings_by_severity', {}).get('low', 0)}")
        
        # Phase Completion Status
        done = summary.get("completed_phases", {})
        if done:
            lines.append("\n### ✅ Completed Phases:")
            for phase, ts in sorted(done.items()):
                lines.append(f"   - `{phase}` @ {ts}")
        lines.append("")

        # --- Detailed Findings (Structured Table) ---
        lines.append("## 🔍 Detailed Findings")
        if findings:
            lines.append("| Severity | Title | Target | CVSS | CWE | MITRE TTP |")
            lines.append("|---|---|---|---|---|---|")
            
            # Sort by severity: critical > high > medium > info
            sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))
            
            for f in sorted_findings:
                # Severity Badge
                badge_map = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}
                sev_icon = badge_map.get(f.severity, '⚫')
                
                # Sanitize evidence for table cells (remove newlines)
                evid_short = f.evidence.replace('\n', ' ')[:50] + ("..." if len(str(f.evidence)) > 50 else "")
                
                lines.append(
                    f"| {sev_icon} **{f.severity.upper()}** | {f.title} | `{f.target}` | "
                    f"{f.metadata.get('cvss', 'N/A') or ''} | {f.metadata.get('cwe', 'N/A') or ''} | "
                    f"{f.metadata.get('mitre_ttp', 'N/A') or ''} |"
                )
            lines.append("")

        # --- Exploit Logs ---
        if logs:
            lines.append("## 💥 Exploitation Log")
            lines.append("| Status | Technique | Target | Access Level | Tool/Method | Session ID |")
            lines.append("|---|---|---|---|---|---|")
            for l in logs:
                icon = "✅" if l.status == "success" else "❌"
                session = l.metadata.get('session_id', 'N/A')
                lines.append(
                    f"| {icon} | `{l.technique}` | `{l.target}` | {l.access_level or 'N/A'} | "
                    f"`{l.tool}` | `{session}` |"
                )
            lines.append("")

        # --- Appendix (Raw Evidence for key findings) ---
        if findings:
            lines.append("## 📎 Raw Evidence Highlights")
            for f in sorted_findings[:5]:  # Top 5 most critical findings first
                lines.append(f"### [{f.severity.upper()}] {f.title} ({f.target})")
                if f.description:
                    lines.append(f"**Description:**\n{f.description}")
                if f.evidence:
                    lines.append(f"**Evidence:**\n```text\n{f.evidence[:500]}\n```")
                lines.append("")

        path = REPORTS_DIR / f"{self._report_name}.md"
        with open(path, "w") as fh:
            fh.write("\n".join(lines))
        return path

    # ------------------------------------------------------------------ #
    # MITRE ATT&CK export
    # ------------------------------------------------------------------ #

    def generate_mitre(self) -> Path:
        """Export findings mapped to MITRE ATT&CK techniques.

        Maps each finding category / exploit log technique to a known
        ATT&CK ID (Txxxx).  Output is a JSONL file — one JSON object
        per row — suitable for downstream ingestion into C2 dashboards
        or custom pivot tables.
        """
        # ── static mappings ────────────────────────────────────────
        CATEGORY_TO_MITRE = {
            "vulnerability":     ("T1190", "Exploit Public-Facing Application"),
            "credential_compromise": ("T1110", "Brute Force"),
            "pivot":             ("T1021", "Remote Services"),
            "remote_shell":      ("T1059", "Command and Scripting Interpreter"),
            "credential_dump":   ("T1003", "OS Credential Dumping"),
            "privesc_vector":    ("T1068", "Exploitation for Privilege Escalation"),
            "access_granted":    ("T1078", "Valid Accounts"),
            "exploit_db_match":  ("T1587", "Develop Capabilities"),
        }

        TECHNIQUE_TO_MITRE = {
            "SSH_Pivot":     ("T1021.004", "SSH"),
            "WinRM_Pivot":   ("T1021.007", "Windows Remote Management"),
            "BruteForce_SSH":    ("T1110.001", "Online Guessing"),
            "BruteForce_FTP":    ("T1110.004", "Password Spraying"),
            "BruteForce_SMTP":   ("T1110.003", "Credential Stuffing"),
        }

        findings = self.kb.get_all_findings()
        logs = self.kb.get_exploit_logs()

        rows: list[dict] = []

        for f in findings:
            mitre_id, mitre_name = CATEGORY_TO_MITRE.get(
                f.category, (f.metadata.get("mitre_ttp", "T1001"), "Unknown")
            )
            rows.append({
                "tactic": "Impact",
                "technique_id": mitre_id,
                "technique_name": mitre_name,
                "source_category": f.category,
                "target": f.target,
                "severity": f.severity,
                "title": f.title,
                "phase": f.phase,
            })

        for l in logs:
            mitre_id, mitre_name = TECHNIQUE_TO_MITRE.get(
                l.technique, (l.metadata.get("mitre_ttp", "T1001"), "Unknown")
            )
            rows.append({
                "tactic": "Execution" if "BruteForce" in l.technique else "Lateral Movement",
                "technique_id": mitre_id,
                "technique_name": mitre_name,
                "target": l.target,
                "tool": l.tool,
                "status": l.status,
            })

        path = REPORTS_DIR / f"{self._report_name}_mitre.jsonl"
        with open(path, "w") as fh:
            for row in rows:
                json.dump(row, fh)
                fh.write("\n")

        return path
