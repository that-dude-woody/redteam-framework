import sqlite3
from urllib.parse import urlparse

c = sqlite3.connect('target_db/knowledge_base.db')
c.row_factory = sqlite3.Row


def norm(t):
    t = (t or '').strip().lower()
    if not t:
        return ''
    p = urlparse(t if '://' in t else f'//{t}')
    return (p.hostname or t).rstrip('.')


scope = ['ozlink.jizzing.space/shipment']
scope_norm = {norm(s) for s in scope}
print('SCOPE normalized:', scope_norm)

print('\n=== Distinct targets in findings + in-scope? ===')
for r in c.execute('SELECT target, COUNT(*) n, MIN(timestamp) mn, MAX(timestamp) mx FROM findings GROUP BY target ORDER BY n DESC'):
    nt = norm(r['target'])
    ins = nt in scope_norm or any(nt.endswith('.' + e) for e in scope_norm if '/' not in e)
    print(f"   {r['target']!r:45} n={r['n']:4}  in_scope={ins}  newest={r['mx']}")

print('\n=== exploit_logs ===')
for r in c.execute('SELECT target, COUNT(*) n, MAX(timestamp) mx FROM exploit_logs GROUP BY target ORDER BY n DESC'):
    print(f"   {r['target']!r:45} n={r['n']:4}  newest={r['mx']}")

print('\n=== metadata (phase_done + target) ===')
for r in c.execute("SELECT key, substr(value,1,70) v FROM metadata WHERE key LIKE 'phase_done:%' OR key LIKE 'target:%' ORDER BY key"):
    print(f"   {r['key']}: {r['v']}")

# Reproduce the engine filter
print('\n=== Simulate engine._filter_findings (current-run OR in-scope) ===')
RUN_START = '2026-08-31T10:06:00.623000+00:00'  # approx engine creation time this run


def is_current_run(ts):
    try:
        return ts >= RUN_START
    except TypeError:
        return False


def in_scope(target):
    e = norm(target)
    if not e:
        return False
    for raw in scope:
        r = norm(raw)
        if e == r or e.endswith('.' + r):
            return True
    return False


kept = []
for r in c.execute('SELECT id, phase, target, timestamp FROM findings ORDER BY timestamp'):
    f = dict(r)
    if is_current_run(f['timestamp']) or in_scope(f['target']):
        kept.append(f)
print(f"   Total findings: {c.execute('SELECT COUNT(*) FROM findings').fetchone()[0]}")
print(f"   Survive filter : {len(kept)}")
for f in kept:
    print(f"      {f['phase']:16} target={f['target']!r:35} ts={f['timestamp']}")
