"""
Run-scope helpers for the red team framework.

Recon and every downstream phase must only operate on the operator's
authorized scope, plus anything legitimately discovered during the current
run. The shared, persistent Knowledge Base is campaign-agnostic, so rows left
over from previous campaigns must be filtered out through this module.
"""

import ipaddress
from typing import Iterable, List
from urllib.parse import urlparse


def normalize_host(target: str) -> str:
    """Reduce a target string to a comparable host.

    Lowercases, strips any URL scheme/path (``https://x/login`` -> ``x``) and a
    trailing dot. IPs pass through unchanged.
    """
    t = (target or "").strip().lower()
    if not t:
        return ""
    parsed = urlparse(t if "://" in t else f"//{t}")
    host = parsed.hostname or t
    return host.rstrip(".")


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def target_in_scope(target: str, scope: Iterable[str]) -> bool:
    """Return True when *target* is covered by an entry in *scope*.

    Matching rules:
      - exact IP / hostname matches
      - CIDR nets cover member IPs (``10.0.0.0/24`` covers ``10.0.0.5``)
      - a domain entry covers its subdomains (``example.com`` covers
        ``api.example.com``); ``evil-example.com`` does *not* match
      - scheme / path prefixes are ignored on both sides
    """
    norm = normalize_host(target)
    if not norm:
        return False

    for entry in scope:
        raw = (entry or "").strip().lower()
        if not raw:
            continue
        # CIDR network (10.0.0.0/24, 2001:db8::/32) — keep the mask intact
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if _is_ip(norm) and ipaddress.ip_address(norm) in net:
                    return True
                continue  # it was a CIDR; nothing more to match against
        # Host or URL entry
        e = normalize_host(raw)
        if not e:
            continue
        if _is_ip(e):
            if norm == e:
                return True
        elif norm == e or norm.endswith("." + e):
            return True
    return False


def get_run_scope(config) -> List[str]:
    """Return the operator scope for a run: config targets + scope_file entries."""
    scope: List[str] = []
    target_cfg = getattr(config, "target", None)
    for t in getattr(target_cfg, "targets", []) or []:
        if isinstance(t, str) and t.strip():
            scope.append(t.strip())
    scope_file = getattr(target_cfg, "scope_file", None)
    if scope_file:
        from pathlib import Path
        try:
            pf = Path(scope_file)
            if pf.is_file():
                for line in pf.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        scope.append(line)
        except OSError:
            pass
    return scope