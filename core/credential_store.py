"""Credential Store for secure management of discovered/tested credentials."""
import json
import sqlite3
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Credential:
    username: str
    password: str
    target: str = "*"
    verified: bool = False
    source: str = "manual"  # e.g., "hydra", "brutespray", "nmap", "config"
    notes: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

class CredentialStore:
    """Two-tier store:
     • JSON-backed default presets (loaded at init)
     • SQLite for runtime-discovered / verified creds
    """

    def __init__(self, db_path: str, cred_json_path: Optional[str] = None):
        self.db_path = db_path
        self._init_db()

        # Load preset credentials from JSON file (operator-tuned)
        self.defaults: dict = {"default_linux": [], "default_windows": [],
                               "password_spray": [], "service_specific": {},
                               "api_keys": {}}
        if cred_json_path:
            self._load_from_json(cred_json_path)

    # ------------------------------------------------------------------ #
    # JSON preset loading
    # ------------------------------------------------------------------ #

    def _load_from_json(self, path: str):
        try:
            with open(path, "r") as fh:
                data = json.load(fh)
            self.defaults.update(data)
        except FileNotFoundError:
            print(f"[!] Credential JSON '{path}' not found — using empty defaults.")

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                target TEXT DEFAULT '*',
                verified BOOLEAN DEFAULT 0,
                source TEXT DEFAULT 'config',
                notes TEXT,
                timestamp TEXT,
                access_level TEXT DEFAULT 'unknown',
                UNIQUE(username, password, target)
            )""")
        conn.commit()

    # ------------------------------------------------------------------ #
    # Convenience helpers — return List[List[str]] (username, password)
    # ------------------------------------------------------------------ #

    def load_creds(self, service: str = "ssh") -> list[list[str]]:
        """Return credentials suitable for the given service / protocol."""
        svc_map = {
            "ssh": ["ssh", "default_linux"],
            "winrm": ["winrm", "default_windows"],
            "smb": ["smb", "default_windows"],
            "rdp": ["rdp", "default_linux"],
            "password_spray": ["password_spray"],
        }
        keys = svc_map.get(service, ["ssh"])
        result: list[list[str]] = []
        seen: set[tuple[str, str]] = set()
        for key in keys:
            if key == "password_spray":
                # Convert ["Pass1","Pass2"] → [["spray_user","Pass1"],["spray_user","Pass2"]]
                for pw in self.defaults.get("password_spray", []):
                    candidate = ("default_user", pw)
                    if candidate not in seen:
                        seen.add(candidate)
                        result.append(list(candidate))
            else:
                for entry in self.defaults.get(key, []) or []:
                    candidate = tuple(entry)
                    if len(candidate) == 2 and candidate not in seen:
                        seen.add(candidate)
                        result.append(list(candidate))
        # Operator-tuned per-service presets (credentials_default.json::service_specific)
        for entry in self.defaults.get("service_specific", {}).get(service, []) or []:
            candidate = tuple(entry)
            if len(candidate) == 2 and candidate not in seen:
                seen.add(candidate)
                result.append(list(candidate))
        return result

    def get_ssh_creds(self) -> list[list[str]]:
        return self.load_creds("ssh")

    def get_winrm_creds(self) -> list[list[str]]:
        return self.load_creds("winrm")

    def get_smb_creds(self) -> list[list[str]]:
        return self.load_creds("smb")

    # ------------------------------------------------------------------ #
    # SQLite persistence for discovered/verified creds
    # ------------------------------------------------------------------ #

    def add_credential(self, cred: Credential):
        try:
            with self._get_conn() as conn:
                conn.execute("""INSERT OR IGNORE INTO credentials 
                    (username, password, target, verified, source, notes, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (cred.username, cred.password, cred.target,
                     cred.verified, cred.source, cred.notes, cred.timestamp))
            conn.commit()
        except Exception as e:
            print(f"[!] Credential Store Error: {e}")

    def get_credentials(self, target: str = None, verified_only: bool = False) -> List[dict]:
        with self._get_conn() as conn:
            q = "SELECT * FROM credentials WHERE 1=1"
            params = []
            if target:
                q += " AND target = ?"
                params.append(target)
            if verified_only:
                q += " AND verified = 1"
            return [dict(row) for row in conn.execute(q, params).fetchall()]

    def mark_verified(self, target, username, password, access_level="unknown"):
        with self._get_conn() as conn:
            conn.execute("UPDATE credentials SET verified=1, access_level=? WHERE target=? AND username=? AND password=?",
                         (access_level, target, username, password))
        conn.commit()