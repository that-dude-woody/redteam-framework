#!/usr/bin/env python3
"""CLI entry point for the red team framework."""

import argparse
import logging
import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).parent))

from core.config import FrameworkConfig, load_default_config
from core.engine import Engine
from core.reporting import Reporter
from core.target_input import resolve_targets, interactive_target_prompt


def main():
    parser = argparse.ArgumentParser(description="Red Team Framework")
    parser.add_argument("--config", "-c", help="Path to JSON config file", default=None)
    parser.add_argument("--campaign", help="Campaign ID override", default=None)
    parser.add_argument("--reset-kb", action="store_true", help="Clear the Knowledge Base before running (fresh start for this campaign)")
    parser.add_argument("--phase", help="Run a single phase only", default=None)
    parser.add_argument("--report-only", action="store_true", help="Generate reports without running phases")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging")
    parser.add_argument("--targets", "-t", help="Comma-separated list of targets (IPs, domains, CIDR ranges)", default=None)
    parser.add_argument("--target-file", "-f", help="Path to text file with targets (one per line)", default=None)
    parser.add_argument("--dry-run", action="store_true", help="Show tasks that would be executed without running them")
    parser.add_argument("--throttle", type=float, default=0.0, help="Minimum seconds between task starts (rate-limiting)")
    parser.add_argument("--export-mitre", action="store_true", help="Export MITRE ATT&CK mappings alongside reports")
    parser.add_argument("--validate-config", action="store_true", help="Validate config file and exit without running")
    args = parser.parse_args()

    # Load config (needed for both validate and normal flow)
    if args.config:
        config = FrameworkConfig.from_file(args.config)
    else:
        config = load_default_config()

    if args.campaign:
        config.campaign_id = args.campaign

    # Validate config if requested
    if args.validate_config:
        valid_phases = {"recon", "discovery", "altdns", "ffuf", "gobuster_vhost", "wpscan",
                        "exploitation", "metasploit_integration", "searchsploit_enrichment",
                        "exploit_logging", "post_exploit", "lateral_movement", "exfiltration"}
        for phase_name, pc in config.phases.items():
            if phase_name not in valid_phases:
                print(f"[!] Unknown phase '{phase_name}' in config")
            else:
                status = "enabled" if pc.enabled else "disabled"
                print(f"    [{status:>7}] {phase_name}: timeout={pc.timeout}s, max_threads={pc.max_threads}")
        # Check credential file
        cred_path = getattr(config, 'credential_file', None)
        if cred_path:
            import json as _json2
            try:
                with open(cred_path) as _fh:
                    _json2.load(_fh)
                print(f"    [ok] Credential file: {cred_path}")
            except FileNotFoundError:
                print(f"    [-] Credential file not found: {cred_path}")
            except _json2.JSONDecodeError:
                print(f"    [!] Credential file malformed: {cred_path}")
        # Check target scope
        if config.target.scope_file:
            import os as _os
            if _os.path.isfile(config.target.scope_file):
                with open(config.target.scope_file) as _fh:
                    scope_lines = [_l.strip() for _l in _fh if _l.strip()]
                print(f"    [ok] Scope file: {config.target.scope_file} ({len(scope_lines)} entries)")
            else:
                print(f"    [-] Scope file not found: {config.target.scope_file}")
        # Check DB directory
        from pathlib import Path as _Path
        db_dir = _Path(config.db_path).parent
        if db_dir.exists():
            print(f"    [ok] Database directory exists: {db_dir}")
        else:
            print(f"    [!] Database directory will be created: {db_dir}")
        print("\nConfig validation complete.")
        return

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Resolve targets (CLI > file > config > interactive prompt)
    targets = resolve_targets(args)
    
    if not targets and config.target.targets:
        targets = config.target.targets
        print(f"[*] Targets from config ({len(targets)}): {', '.join(targets)}")
    
    if not targets:
        # No targets anywhere — fall back to interactive prompt
        print("[!] No targets specified. Launching interactive input...")
        targets = interactive_target_prompt()
    
    config.target.targets = targets
    print(f"\n[*] Framework configured with {len(targets)} target(s)")

    engine = Engine(config, throttle=args.throttle)

    if args.reset_kb:
        print("[*] Resetting Knowledge Base for fresh campaign...")
        cleared_findings, cleared_logs = engine.kb.clear_all()
        print(f"[*] Cleared {cleared_findings} findings and {cleared_logs} exploit logs")

    if args.report_only:
        Reporter(config, engine.kb).generate()
        if args.export_mitre:
            Reporter(config, engine.kb).generate_mitre()
        print("Reports generated.")
        return

    # Dry-run: show tasks without executing
    if args.dry_run:
        from core.config import get_phase_order
        all_tasks = []
        for phase_name in get_phase_order():
            if not engine._is_enabled(phase_name):
                continue
            HandlerClass = engine._load_phase_module(phase_name)
            prior_findings = engine._filter_findings(engine.kb.get_all_findings())
            prior_logs = engine._filter_logs(engine.kb.get_exploit_logs())
            handler = HandlerClass(
                config=engine.config, kb=engine.kb,
                cred_store=engine.cred_store,
                prior_findings=prior_findings,
                prior_exploit_logs=prior_logs,
            )
            tasks = handler.build_task_list()
            all_tasks.extend((phase_name, t) for t in tasks)

        print(f"\n--- Dry Run ({len(all_tasks)} tasks would execute) ---")
        for phase_name, task in all_tasks:
            action = task.get("action") or task.get("type", "?")
            print(f"  [{phase_name}] {action} → {task.get('target', 'N/A')}")
        print("Done. Use without --dry-run to execute.")
        return

    if args.phase:
        engine.run_single(args.phase)
    else:
        engine.run()

    # Print status summary
    import json as _json
    print("\n--- Execution Status ---")
    print(_json.dumps(engine.status(), indent=2))
    print("\n--- KB Summary ---")
    print(_json.dumps(engine.kb_summary(), indent=2))

    # Generate reports
    Reporter(config, engine.kb).generate()
    if args.export_mitre:
        Reporter(config, engine.kb).generate_mitre()
    from core.config import REPORTS_DIR
    print(f"\nReports written to {REPORTS_DIR}")


if __name__ == "__main__":
    main()
