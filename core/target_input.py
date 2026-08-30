"""
Interactive target input for the red team framework.
Supports CLI flags, interactive prompt, multi-target entry, and file loading.
"""

import sys
from pathlib import Path


def load_targets_from_file(filepath: str) -> list[str]:
    """Load targets from a text file (one per line, comments with #)."""
    path = Path(filepath)
    if not path.exists():
        print(f"[!] Target file not found: {filepath}")
        return []
    
    targets = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    
    print(f"[*] Loaded {len(targets)} target(s) from {filepath}")
    return targets


def interactive_target_prompt() -> list[str]:
    """Interactive prompt for operator to input targets."""
    print("\n========================================")
    print("  Red Team Framework - Target Input")
    print("========================================")
    print("\nOptions:")
    print("  1) Enter targets interactively (one at a time)")
    print("  2) Paste comma-separated list of targets")
    print("  3) Load targets from a file (.txt, one per line)")
    print("  q) Quit")
    print()
    
    choice = input("[?] Select option > ").strip().lower()
    
    if choice == "q":
        print("[!] No targets provided. Aborting.")
        sys.exit(0)
    
    elif choice == "1":
        targets = []
        print("[*] Enter targets one at a time (IP, domain, CIDR). Type 'done' when finished.\n")
        while True:
            target = input("  [+] Target > ").strip()
            if not target:
                continue
            if target.lower() == "done":
                break
            targets.append(target)
        
        if not targets:
            print("[!] No targets entered. Aborting.")
            sys.exit(0)
    
    elif choice == "2":
        raw = input("[*] Enter comma-separated targets > ").strip()
        targets = [t.strip() for t in raw.split(",") if t.strip()]
        if not targets:
            print("[!] No targets entered. Aborting.")
            sys.exit(0)
    
    elif choice == "3":
        filepath = input("[*] Enter path to target file > ").strip()
        targets = load_targets_from_file(filepath)
        if not targets:
            sys.exit(1)
    
    else:
        print("[!] Invalid option. Aborting.")
        sys.exit(1)
    
    print(f"\n[*] Confirmed targets ({len(targets)}):")
    for t in targets:
        print(f"      - {t}")
    
    return targets


def resolve_targets(args) -> list[str]:
    """Resolve targets from CLI args, file, or interactive prompt.
    
    Priority order:
      1. --targets CLI flag
      2. --target-file CLI flag
      3. --config JSON file (if it has targets defined)
      4. Interactive prompt
    """
    targets = []
    
    # Priority 1: --targets flag
    if hasattr(args, "targets") and args.targets:
        targets = [t.strip() for t in args.targets.split(",") if t.strip()]
        print(f"[*] Targets from CLI ({len(targets)}): {', '.join(targets)}")
        return targets
    
    # Priority 2: --target-file flag
    if hasattr(args, "target_file") and args.target_file:
        targets = load_targets_from_file(args.target_file)
        if targets:
            return targets
    
    # Priority 3: Will be checked against loaded config in main()
    # Priority 4: Interactive prompt (only if no targets after config load)
    return targets
