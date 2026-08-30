"""
Orchestration engine for the red team framework.

Runs phases sequentially in the configured order. Each phase ingests the full
accumulated KB state before building its own task list, which it can execute
internally with parallel workers via a thread pool.
"""

import importlib
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Callable, Optional

from core.config import FrameworkConfig, get_phase_order
from core.credential_store import CredentialStore
from core.knowledge_base import KnowledgeBase
from core.scope import get_run_scope, target_in_scope

log = logging.getLogger(__name__)


class PhaseResult:
    """Container for a phase execution result."""

    def __init__(self, name: str):
        self.name = name
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None
        self.success = False
        self.error: Optional[str] = None
        self.tasks_executed = 0
        self.findings_count = 0

    @property
    def duration(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0


class Engine:
    """Main orchestrator — runs phases in order, wires KB through the chain."""

    def __init__(self, config: FrameworkConfig, throttle: float = 0.0):
        """Initialize engine with optional throttling between task starts.

        Args:
            config: Framework configuration.
            throttle: Minimum seconds between consecutive task start times
                      across all phases.  Zero disables throttling.
        """
        self.config = config
        self.kb = KnowledgeBase(config.db_path)
        self._throttle = throttle
        # Strict run scoping: phases only ever see (a) rows created during this
        # engine run and (b) rows whose target falls inside the operator scope.
        # The shared persistent KB is campaign-agnostic, so historical rows from
        # previous campaigns must be filtered out or we'd scan stale targets.
        self._scope = get_run_scope(config)
        self._run_start: Optional[datetime] = datetime.now(timezone.utc)
        # Wire up credential store so phases never need hardcoded passwords
        self.cred_store = CredentialStore(
            db_path=config.db_path,
            cred_json_path=getattr(config, "credential_file", None),
        )
        self.results: dict[str, PhaseResult] = {}

    @property
    def throttle(self) -> float:
        """Current per-task delay interval."""
        return self._throttle

    @throttle.setter
    def throttle(self, value: float):
        self._throttle = max(0.0, float(value))

    # ------------------------------------------------------------------ #
    # Public entry point
    # ------------------------------------------------------------------ #

    def run(self):
        """Execute all enabled phases in order."""
        phase_order = get_phase_order()
        for phase_name in phase_order:
            if not self._is_enabled(phase_name):
                log.info("Phase '%s' disabled, skipping", phase_name)
                continue
            self._run_phase(phase_name)

    def run_single(self, phase_name: str):
        """Run a single phase (useful for testing / re-execution)."""
        self._run_phase(phase_name)

    # ------------------------------------------------------------------ #
    # Run-scope helpers
    # ------------------------------------------------------------------ #

    def _is_current_run(self, timestamp: str) -> bool:
        """True for rows written after this Engine instance was created."""
        try:
            return timestamp >= self._run_start.isoformat()
        except TypeError:
            return False

    def _in_scope(self, target: str) -> bool:
        """True when a target falls within the operator-supplied scope."""
        return target_in_scope(target, self._scope)

    def _filter_findings(self, findings) -> list:
        """Keep only in-scope findings or findings produced during this run."""
        return [f for f in findings
                if self._is_current_run(f.timestamp) or self._in_scope(f.target)]

    def _filter_logs(self, logs) -> list:
        """Keep only in-scope exploit logs or logs produced during this run."""
        return [l for l in logs
                if self._is_current_run(l.timestamp) or self._in_scope(l.target)]

    # ------------------------------------------------------------------ #
    # Phase lifecycle
    # ------------------------------------------------------------------ #

    def _is_enabled(self, phase_name: str) -> bool:
        phase_cfg = self.config.phases.get(phase_name)
        return phase_cfg and phase_cfg.enabled if phase_cfg else False

    def _load_phase_module(self, phase_name: str):
        """Dynamically import phases/<phase_name>.py and return its class."""
        mod = importlib.import_module(f"phases.{phase_name}")
        # Convention: each module exposes a class named after the phase (snake_case)
        cls = getattr(mod, phase_name)
        return cls

    def _run_phase(self, phase_name: str):
        """Full lifecycle for one phase: ingest KB → execute → mark done."""
        result = PhaseResult(phase_name)
        self.results[phase_name] = result
        result.start_time = time.time()

        try:
            phase_cfg = self.config.phases.get(phase_name)
            max_workers = phase_cfg.max_threads if phase_cfg else 4
            timeout = phase_cfg.timeout if phase_cfg else 3600

            # 1. Ingest the full accumulated KB state, filtered to the current
            #    run + operator scope (never rows from prior campaigns).
            all_findings = self._filter_findings(self.kb.get_all_findings())
            all_logs = self._filter_logs(self.kb.get_exploit_logs())

            log.info(
                ">>> Phase [%s] starting — KB has %d findings, %d exploit logs",
                phase_name, len(all_findings), len(all_logs),
            )

            # 2. Instantiate the phase handler and pass full context including credentials
            HandlerClass = self._load_phase_module(phase_name)
            handler = HandlerClass(
                config=self.config,
                kb=self.kb,
                cred_store=self.cred_store,
                prior_findings=all_findings,
                prior_exploit_logs=all_logs,
            )

            # 3. Let the phase build its own task list from context
            tasks = handler.build_task_list()
            log.info("Phase [%s] generated %d tasks", phase_name, len(tasks))

            if not tasks:
                log.info("Phase [%s] — no tasks, finishing immediately", phase_name)
                # Still mark the phase complete so the campaign report reflects it ran
                self.kb.phase_completed(phase_name)
                result.success = True
                result.end_time = time.time()
                return

            # 4. Execute tasks with internal parallelism via thread pool
            executed = 0; failed = 0
            per_task_timeout = min(timeout // max(len(tasks), 1), 300)  # ~5min per task max
            last_submit_time = time.time()
            futures: dict = {}
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                for i, task in enumerate(tasks):
                    # Rate-limiting: enforce minimum gap between submits
                    if self._throttle > 0 and i > 0:
                        elapsed = time.time() - last_submit_time
                        delay = self._throttle - elapsed
                        if delay > 0:
                            time.sleep(delay)
                    last_submit_time = time.time()
                    fut = pool.submit(handler.execute_task, task)
                    futures[fut] = task
                for fut in as_completed(futures, timeout=timeout):
                    try:
                        fut.result(timeout=per_task_timeout)
                        executed += 1
                    except Exception as exc:
                        failed += 1
                        log.warning(
                            "Task %s in phase [%s] failed: %s",
                            futures[fut], phase_name, exc,
                        )
            if failed:
                log.info("Phase [%s] — %d/%d tasks failed (timeout or error)", phase_name, failed, len(tasks))

            result.tasks_executed = executed
            result.findings_count = len(self.kb.get_findings(phases=[phase_name]))
            result.success = True

            # 5. Mark phase complete in KB metadata
            self.kb.phase_completed(phase_name)

        except Exception as exc:
            log.exception("Phase [%s] crashed: %s", phase_name, exc)
            result.error = str(exc)
            result.success = False

        finally:
            result.end_time = time.time()
            log.info(
                ">>> Phase [%s] finished in %.1fs (tasks=%d, findings=%d, success=%s)",
                phase_name,
                result.duration,
                result.tasks_executed,
                result.findings_count,
                result.success,
            )

    # ------------------------------------------------------------------ #
    # Status helpers
    # ------------------------------------------------------------------ #

    def status(self) -> dict:
        """Return human-readable status of all run phases."""
        return {
            name: {
                "success": r.success,
                "duration": round(r.duration, 2),
                "tasks_executed": r.tasks_executed,
                "findings_count": r.findings_count,
                "error": r.error,
            }
            for name, r in self.results.items()
        }

    def kb_summary(self) -> dict:
        """Delegate to KB summary."""
        return self.kb.summary()
