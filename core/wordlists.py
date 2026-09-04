"""SecLists / wordlist location resolution, shared by the fuzz phases.

The fuzzing phases (ffuf, gobuster_vhost) need a wordlist file, but the
classic install locations are Linux-only.  On macOS the lists are usually
cloned somewhere local.  This module centralizes resolution so the phases
agree, and makes the location configurable via the ``SECLISTS_DIR``
(fallback ``WORDLISTS_DIR``) environment variable.
"""
import logging
import os

log = logging.getLogger(__name__)

# Root locations, in priority order.  The first that contains the requested
# file wins.
_ROOT_CANDIDATES = [
     "/usr/share/seclists",
     "/opt/homebrew/share/seclists",
     "/usr/local/share/seclists",
     # Common user-local SecLists checkouts.
     "~/Documents/Wordlists/SecLists",
     "~/SecLists",
]

# Relative paths to try, in priority order, for each category.
_REL = {
     "web": [
         "Discovery/Web-Content/common.txt",
         "Discovery/Web-Content/big.txt",
     ],
     "vhosts": [
         "Discovery/DNS/subdomains-top1million-5000.txt",
         "Discovery/DNS/subdomains-top1million-20000.txt",
         "Discovery/DNS/combined_subdomains.txt",
         "Discovery/DNS/subdomain-top1million.txt",
     ],
}

# Legacy absolute fallbacks (explicit installs / back-compat).
_LEGACY = {
     "web": [
         "/usr/share/wordlists/dirb/big.txt",
         "/usr/share/seclists/Discovery/Web-Content/common.txt",
     ],
     "vhosts": [
         "/usr/share/gobuster/data/dns.txt",
         "/usr/share/seclists/Discovery/DNS/subdomain-top1million.txt",
     ],
}


def seclists_roots() -> list[str]:
    """Ordered, de-duplicated list of SecLists root dirs to search.

    Honors ``SECLISTS_DIR`` (fallback ``WORDLISTS_DIR``) first, then the
    well-known package locations, then common user-local checkouts.
    """
    roots = []
    env_root = os.environ.get("SECLISTS_DIR") or os.environ.get("WORDLISTS_DIR")
    if env_root:
        roots.append(os.path.expanduser(env_root))
    roots.extend(os.path.expanduser(r) for r in _ROOT_CANDIDATES)

    seen: set[str] = set()
    out: list[str] = []
    for r in roots:
        r = r.rstrip("/")
        if r and r not in seen:
            seen.add(r)
            out.append(r)
    return out


def resolve(category: str) -> str:
    """Return the first existing wordlist path for a category.

    ``category`` is ``"web"`` (directory fuzzing) or ``"vhosts"``
    (subdomain/vhost discovery).  If nothing is found, a clear warning is
    logged and the conventional default path is returned; callers already
    treat a non-zero tool exit as "nothing found", so this fails safely.
    """
    rel = _REL.get(category, [])
    roots = seclists_roots()
    for root in roots:
        for name in rel:
            candidate = os.path.join(root, name)
            if os.path.isfile(candidate):
                return candidate
    for path in _LEGACY.get(category, []):
        if os.path.isfile(path):
            return path

    default = os.path.join(
        roots[0] if roots else "/usr/share/seclists",
        rel[0] if rel else "Discovery/Web-Content/common.txt",
    )
    log.warning(
        "wordlist: no '%s' wordlist found in %s; using %s "
        "(the tool will likely exit non-zero). Set SECLISTS_DIR or install SecLists.",
        category, roots, default,
    )
    return default