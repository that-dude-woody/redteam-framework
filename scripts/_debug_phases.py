import os, sys, json, socket, sqlite3
sys.path.insert(0, os.getcwd())

print("=== 1. The 2 in-scope findings (full detail) ===")
c = sqlite3.connect('target_db/knowledge_base.db')
c.row_factory = sqlite3.Row
rows = c.execute("SELECT * FROM findings WHERE target LIKE 'ozlink%' ORDER BY timestamp").fetchall()
for r in rows:
    d = dict(r)
    d['metadata'] = json.loads(d['metadata'] or '{}')
    print("  phase=%-8s cat=%-18s sev=%-8s target=%s ts=%s" % (
        d['phase'], d['category'], d['severity'], d['target'], d['timestamp']))
    print("     title:", d['title'])
    print("     meta:", json.dumps(d['metadata'])[:200])
print("  >> categories of in-scope findings:", [dict(r)['category'] for r in rows])

print("\n=== 2. Wordlist resolution (core.wordlists) ===")
from core.wordlists import resolve, seclists_roots
for cat in ('web', 'vhosts'):
    p = resolve(cat)
    print("  %-6s -> %s  exists=%s" % (cat, p, os.path.isfile(p)))
print("  roots:", seclists_roots())

print("\n=== 3. Target DNS resolution ===")
for host in ('ozlink.jizzing.space', 'jizzing.space'):
    try:
        print("  %-25s -> %s" % (host, socket.gethostbyname(host)))
    except Exception as e:
        print("  %-25s -> RESOLVE FAILED: %s" % (host, e))

print("\n=== 4. Simulate each phase build_task_list with the FILTERED (in-scope) findings ===")
from core.knowledge_base import KnowledgeBase, Finding
from core.scope import normalize_host, target_in_scope, get_run_scope
from core.config import load_default_config

cfg = load_default_config()
cfg.target.targets = ['ozlink.jizzing.space/shipment']
kb = KnowledgeBase(cfg.db_path)
scope = get_run_scope(cfg)

def is_current(ts):
    return ts >= '2026-08-31T10:06:00.000000+00:00'

all_f = kb.get_all_findings()
filtered = [f for f in all_f if is_current(f.timestamp) or target_in_scope(f.target, scope)]
print("  all findings=%d  filtered(in-scope/current-run)=%d" % (len(all_f), len(filtered)))

for phase in ['discovery', 'ffuf', 'gobuster_vhost', 'altdns', 'exploitation', 'metasploit_integration', 'wpscan']:
    import importlib
    mod = importlib.import_module(f'phases.{phase}')
    cls = getattr(mod, phase)
    try:
        h = cls(config=cfg, kb=kb, cred_store=None, prior_findings=filtered, prior_exploit_logs=[])
        tasks = h.build_task_list()
        print("  %-22s -> %d task(s): %s" % (phase, len(tasks), tasks[:3]))
    except Exception as e:
        print("  %-22s -> ERROR: %r" % (phase, e))

print("\n=== 5. Does the target carry a PATH into phase URLs? ===")
for t in cfg.target.targets:
    print("  raw target=%-30s normalized_host=%s" % (t, normalize_host(t)))
