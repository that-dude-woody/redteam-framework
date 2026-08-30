"""
Centralized configuration for the red team framework.
Handles operator settings, target scope, phase execution order, and reporting format.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent
REPORTS_DIR = BASE_DIR / "reports"
DB_DIR = BASE_DIR / "target_db"


@dataclass
class TargetConfig:
    """Target environment configuration"""
    targets: List[str] = field(default_factory=list)  # IPs, domains, or ranges
    target_os: str = "mixed"  # macos, windows, linux, mixed
    authorized: bool = True   # Full authority assumed per operator preference
    logging_enabled: bool = True  # Log exploitation for proof of access
    scope_file: Optional[str] = None  # Path to approved scope list


@dataclass
class PhaseConfig:
    """Individual phase configuration"""
    enabled: bool = True
    timeout: int = 3600  # seconds
    max_threads: int = 4
    options: Dict = field(default_factory=dict)


@dataclass
class FrameworkConfig:
    """Master framework configuration"""
    operator_name: str = "operator"
    campaign_id: str = "CAMPAIGN-001"
    target: TargetConfig = field(default_factory=TargetConfig)
    phases: Dict[str, PhaseConfig] = field(default_factory=lambda: {
        "recon": PhaseConfig(enabled=True, timeout=1800),
        "discovery": PhaseConfig(enabled=True, timeout=3600),
        "altdns": PhaseConfig(enabled=False, timeout=1800),
        "ffuf": PhaseConfig(enabled=True, timeout=1800),
        "gobuster_vhost": PhaseConfig(enabled=True, timeout=1800),
        "wpscan": PhaseConfig(enabled=True, timeout=1800),
        "exploitation": PhaseConfig(enabled=True, timeout=7200),
        "metasploit_integration": PhaseConfig(enabled=False, timeout=3600),
        "searchsploit_enrichment": PhaseConfig(enabled=True, timeout=1800),
        "exploit_logging": PhaseConfig(enabled=True, timeout=3600),
        "post_exploit": PhaseConfig(enabled=True, timeout=3600),
        "lateral_movement": PhaseConfig(enabled=True, timeout=3600),
        "exfiltration": PhaseConfig(enabled=True, timeout=1800),
    })
    report_format: List[str] = field(default_factory=lambda: ["json", "markdown"])
    db_path: str = str(DB_DIR / "knowledge_base.db")
    credential_file: str = str(BASE_DIR / "credentials_default.json")

    @classmethod
    def from_file(cls, path: str) -> "FrameworkConfig":
        with open(path, 'r') as f:
            data = json.load(f)
        # Reconstruct nested dataclasses
        target_data = data.pop("target", {})
        target = TargetConfig(**target_data)
        phases_data = data.pop("phases", {})
        phases = {}
        for phase_name, phase_opts in phases_data.items():
            phases[phase_name] = PhaseConfig(**phase_opts)
        data["target"] = target
        data["phases"] = phases
        return cls(**data)

    def save(self, path: str):
        # Convert to plain dict for serialization
        d = asdict(self)
        with open(path, 'w') as f:
            json.dump(d, f, indent=2)


def load_default_config() -> FrameworkConfig:
    """Return default configuration optimized for macOS/Windows/Linux mixed environments"""
    config = FrameworkConfig(
        operator_name="operator",
        campaign_id="CAMPAIGN-001",
        target=TargetConfig(
            target_os="mixed",
            authorized=True,
            logging_enabled=True,
        ),
    )
    return config


def get_phase_order() -> List[str]:
    """Return the execution order of phases"""
    return [
        "recon",
        "discovery",
        "altdns",
        "ffuf",
        "gobuster_vhost",
        "wpscan",
        "exploitation",
        "metasploit_integration",
        "searchsploit_enrichment",
        "exploit_logging",
        "post_exploit",
        "lateral_movement",
        "exfiltration"
    ]
