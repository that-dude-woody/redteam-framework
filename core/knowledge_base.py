"""
SQLite-backed Knowledge Base for the red team framework.

Acts as the single source of truth across all phases. Each phase writes structured
findings here; every subsequent phase ingests the full accumulated state before
generating its own task list.
"""

import sqlite3
import json
import time
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from contextlib import contextmanager

log = logging.getLogger(__name__)

@dataclass
class Finding:
    """Generic finding record stored in the KB"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    phase: str = ""
    target: str = ""
    category: str = ""  # e.g. "port", "service", "vuln", "cred", "asset"
    severity: str = "info"  # info, low, medium, high, critical
    title: str = ""
    description: str = ""
    evidence: str = ""       # raw output, hashes, screenshots path, etc.
    metadata: dict = field(default_factory=dict)   # arbitrary key/value
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@dataclass
class ExploitLog:
    """Structured log of an exploitation attempt/result"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    target: str = ""
    technique: str = ""
    tool: str = ""
    command: str = ""
    status: str = "pending"  # pending, success, failure, partial
    access_level: str = ""   # e.g. "user", "admin", "root", "SYSTEM"
    output_hash: str = ""    # SHA256 of captured output for dedup
    raw_output_path: str = ""
    metadata: dict = field(default_factory=dict)  # arbitrary key/value (e.g. session_id, tool_version)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


@contextmanager
def _get_connection(db_path: str, persistent_conn=None):
    """Yield a connection with WAL mode and row factory set."""
    if persistent_conn is not None:
        yield persistent_conn
        return
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


class KnowledgeBase:
    """Central storage layer used by all phases and the engine."""

    _SCHEMA_VERSION = 3
    # Shared in-memory connection cache (avoid per-connection isolation).
    _memory_conn = None

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._is_memory = (db_path == ":memory:")
        if self._is_memory:
            KnowledgeBase._memory_conn = sqlite3.connect(":memory:")
            KnowledgeBase._memory_conn.row_factory = sqlite3.Row
        self._init_schema()

    def _conn_kw(self):
        return {"persistent_conn": KnowledgeBase._memory_conn} if self._is_memory else {}

    # ------------------------------------------------------------------ #
    # Schema management
    # ------------------------------------------------------------------ #

    def _init_schema(self):
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id        TEXT PRIMARY KEY,
                    phase     TEXT NOT NULL,
                    target    TEXT NOT NULL,
                    category  TEXT NOT NULL,
                    severity  TEXT NOT NULL DEFAULT 'info',
                    title     TEXT NOT NULL,
                    description TEXT,
                    evidence  TEXT,
                    metadata  TEXT,   -- JSON blob
                    timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(phase);
                CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

                CREATE TABLE IF NOT EXISTS exploit_logs (
                    id            TEXT PRIMARY KEY,
                    target        TEXT NOT NULL,
                    technique     TEXT NOT NULL,
                    tool          TEXT NOT NULL,
                    command       TEXT NOT NULL,
                    status        TEXT NOT NULL DEFAULT 'pending',
                    access_level  TEXT,
                    output_hash   TEXT,
                    raw_output_path TEXT,
                    metadata      TEXT,
                    timestamp     TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_exploit_logs_target ON exploit_logs(target);
                CREATE INDEX IF NOT EXISTS idx_exploit_logs_status ON exploit_logs(status);

                INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '3');
            """)

    # ------------------------------------------------------------------ #
    # Findings API
    # ------------------------------------------------------------------ #

    def add_finding(self, finding: Finding):
        """Persist a single finding with data quality validation."""
        # Data quality gate: reject junk findings
        if not finding.title or not finding.title.strip():
            log = logging.getLogger(__name__)
            log.debug("Rejected finding with empty title: phase=%s category=%s target=%s",
                      finding.phase, finding.category, finding.target)
            return False
        # For info/low severity, require either a description or evidence
        if finding.severity in ("info", "low"):
            has_desc = bool(finding.description and finding.description.strip())
            has_evidence = bool(finding.evidence and finding.evidence.strip())
            if not has_desc and not has_evidence:
                log = logging.getLogger(__name__)
                log.debug("Rejected info/low finding with no description or evidence: id=%s", finding.id)
                return False
        m = asdict(finding)
        m["metadata"] = json.dumps(m["metadata"])
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, phase, target, category, severity, title, description, evidence, metadata, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    m["id"], m["phase"], m["target"], m["category"],
                    m["severity"], m["title"], m["description"],
                    m["evidence"], m["metadata"], m["timestamp"],
                ),
            )
            conn.commit()
        return True

    def add_findings(self, findings: list[Finding]):
        for f in findings:
            self.add_finding(f)

    def get_findings(
        self,
        phases: Optional[list[str]] = None,
        target: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> list[Finding]:
        """Query findings with optional filters."""
        clauses = []
        params: list = []
        if phases:
            placeholders = ",".join("?" * len(phases))
            clauses.append(f"phase IN ({placeholders})")
            params.extend(phases)
        if target:
            clauses.append("target = ?")
            params.append(target)
        if category:
            clauses.append("category = ?")
            params.append(category)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        where = " AND ".join(clauses) if clauses else "1=1"

        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            rows = conn.execute(
                f"SELECT * FROM findings WHERE {where} ORDER BY timestamp",
                params,
            ).fetchall()

        results = []
        for r in rows:
            row = dict(r)
            row["metadata"] = json.loads(row["metadata"]) if row.get("metadata") else {}
            results.append(Finding(**row))
        return results

    def get_all_findings(self) -> list[Finding]:
        """Return every finding — used by phases that need full historical state."""
        return self.get_findings()

    # ------------------------------------------------------------------ #
    # Exploit log API
    # ------------------------------------------------------------------ #

    def add_exploit_log(self, log: ExploitLog):
        m = asdict(log)
        m["metadata"] = json.dumps(m["metadata"]) if m["metadata"] else None
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            # Support both old (no metadata column) and new schemas
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO exploit_logs
                       (id, target, technique, tool, command, status, access_level,
                        output_hash, raw_output_path, metadata, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    tuple(m.values()),
                )
            except sqlite3.OperationalError:
                # Old schema without metadata column — fall back
                conn.execute(
                    """INSERT OR REPLACE INTO exploit_logs
                       (id, target, technique, tool, command, status, access_level,
                        output_hash, raw_output_path, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    tuple(v for k, v in m.items() if k != "metadata"),
                )
            conn.commit()

    def get_exploit_logs(
        self,
        target: Optional[str] = None,
        status: Optional[str] = None,
    ) -> list[ExploitLog]:
        clauses = []
        params: list = []
        if target:
            clauses.append("target = ?")
            params.append(target)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = " AND ".join(clauses) if clauses else "1=1"

        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            rows = conn.execute(
                f"SELECT * FROM exploit_logs WHERE {where} ORDER BY timestamp",
                params,
            ).fetchall()

        results = []
        for r in rows:
            row = dict(r)
            # Old schema rows won't have a metadata column — default to {}
            if "metadata" not in row or not row["metadata"]:
                row["metadata"] = {}
            else:
                row["metadata"] = json.loads(row["metadata"])
            results.append(ExploitLog(**row))
        return results

    def update_exploit_log_status(self, log_id: str, status: str) -> bool:
        """Set the status of an exploit log by id, preserving all other fields."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            cur = conn.execute(
                "UPDATE exploit_logs SET status = ? WHERE id = ?", (status, log_id)
            )
            conn.commit()
            return cur.rowcount > 0

    # ------------------------------------------------------------------ #
    # Convenience helpers used by engine / reporting
    # ------------------------------------------------------------------ #

    def phase_completed(self, phase: str):
        """Mark a phase as completed in metadata."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (f"phase_done:{phase}", datetime.now(timezone.utc).isoformat()),
            )
            conn.commit()

    def get_completion_status(self) -> dict[str, str]:
        """Return {phase: timestamp} for completed phases."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            rows = conn.execute(
                "SELECT key, value FROM metadata WHERE key LIKE 'phase_done:%'"
            ).fetchall()
        return {r[0].split(":", 1)[1]: r[1] for r in rows}

    def delete_findings_by_category(self, category: str) -> int:
        """Delete all findings matching a specific category. Returns count deleted."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM findings WHERE category = ?", (category,))
            before = cur.fetchone()[0]
            conn.execute("DELETE FROM findings WHERE category = ?", (category,))
            conn.commit()
        return before

    def delete_findings_with_empty_title(self) -> int:
        """Delete all findings where title is empty or whitespace-only. Returns count deleted."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            cur = conn.execute("SELECT COUNT(*) FROM findings WHERE (title IS NULL OR TRIM(title) = '')")
            before = cur.fetchone()[0]
            conn.execute("DELETE FROM findings WHERE (title IS NULL OR TRIM(title) = '')")
            conn.commit()
        return before

    def delete_findings_with_empty_evidence_and_description(self, severity: str = "info") -> int:
        """Delete info-severity findings that have neither description nor evidence. Returns count deleted."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            cur = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity = ? AND (description IS NULL OR TRIM(description) = '') AND (evidence IS NULL OR TRIM(evidence) = '')",
                (severity,)
            )
            before = cur.fetchone()[0]
            conn.execute(
                "DELETE FROM findings WHERE severity = ? AND (description IS NULL OR TRIM(description) = '') AND (evidence IS NULL OR TRIM(evidence) = '')",
                (severity,)
            )
            conn.commit()
        return before

    def summary(self) -> dict:
        """Quick overview of KB contents."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            log_count = conn.execute("SELECT COUNT(*) FROM exploit_logs").fetchone()[0]
            by_phase = {
                r[0]: r[1] for r in conn.execute(
                    "SELECT phase, COUNT(*) FROM findings GROUP BY phase"
                ).fetchall()
            }
            by_severity = {
                r[0]: r[1] for r in conn.execute(
                    "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                ).fetchall()
            }
        return {
            "total_findings": finding_count,
            "total_exploit_logs": log_count,
            "findings_by_phase": by_phase,
            "findings_by_severity": by_severity,
            "completed_phases": self.get_completion_status(),
        }

    def clear_all(self) -> tuple[int, int]:
        """Delete all findings and exploit logs for a fresh campaign start. Returns (findings_deleted, logs_deleted)."""
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            f_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            l_count = conn.execute("SELECT COUNT(*) FROM exploit_logs").fetchone()[0]
            conn.execute("DELETE FROM findings")
            conn.execute("DELETE FROM exploit_logs")
            conn.execute("DELETE FROM metadata WHERE key LIKE 'phase_done:%'")
            conn.commit()
        return f_count, l_count

    # ------------------------------------------------------------------ #
    # Target discovery helpers used by recon phase
    # ------------------------------------------------------------------ #

    def store_target_info(self, target: str, **kwargs):
        """Store extra info (type, ports, services) for a target in metadata.

        Args:
            target: The target host/IP.
            **kwargs: Extra fields to persist — e.g. type="domain", ports={...}, services=[...].
        """
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            row = conn.execute(
                "SELECT value FROM metadata WHERE key = ?", (f"target:{target}",)
            ).fetchone()
            data = json.loads(row[0]) if row else {}
            data.update(kwargs)
            # Persist the target name so get_discovered_targets() can recover it
            data.setdefault("name", target)
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (f"target:{target}", json.dumps(data)),
            )
            conn.commit()

    def get_discovered_targets(self) -> list[str]:
        """Return unique target names that have been discovered / stored.

        Checks both explicit target:metadata keys and any findings whose phase
        was 'recon' or 'discovery'.
        """
        targets_set: set[str] = set()
        with _get_connection(self.db_path, **self._conn_kw()) as conn:
            rows = conn.execute(
                "SELECT value FROM metadata WHERE key LIKE 'target:%'"
            ).fetchall()

            # Also collect from prior recon/discovery findings as a fallback
            for row in rows:
                data = json.loads(row[0]) if row and row[0] else {}
                name = data.get("name") or data.get("target", "")
                if name:
                    targets_set.add(name.lower().strip("."))

            # If nothing is stored yet, look at findings with recon/discovery phase
            if not targets_set:
                for cat in ("recon", "discovery"):
                    for r in conn.execute(
                        "SELECT DISTINCT target FROM findings WHERE phase = ?", (cat,)
                    ).fetchall():
                        targets_set.add(r[0].lower().strip("."))

        return sorted(targets_set) if targets_set else []
