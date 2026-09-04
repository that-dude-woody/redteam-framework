import os, sys, time, logging
sys.path.insert(0, os.getcwd())
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from core.config import load_default_config
from core.knowledge_base import KnowledgeBase
from core.scope import get_run_scope, target_in_scope
from phases.discovery import discovery

cfg = load_default_config()
cfg.target.targets = ["ozlink.jizzing.space"]          # NOTE: no path, clean host
cfg.db_path = "/tmp/discovery_test_kb.db"
if os.path.exists(cfg.db_path):
    os.remove(cfg.db_path)

kb = KnowledgeBase(cfg.db_path)
scope = get_run_scope(cfg)
handler = discovery(config=cfg, kb=kb, cred_store=None, prior_findings=[], prior_exploit_logs=[])

tasks = handler.build_task_list()
print("TASKS:", tasks)
for t in tasks:
    handler.execute_task(t)

findings = kb.get_all_findings()
print("TOTAL FINDINGS:", len(findings))
for f in findings:
    print("  ", f.category, f.target, f.title, f"port={f.metadata.get('port')}")
