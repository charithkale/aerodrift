"""The AeroDrift watcher: collect -> graph -> detect -> plan -> generate -> (dry-run|apply) -> verify."""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Optional

from .drift import Change, Finding, diff_states, drifted_resources, evaluate
from .models import CloudState
from .remediation import Action, execute, generate_source, plan_remediation
from .store import Store


@dataclass
class CycleResult:
    state: CloudState
    findings: list
    changes: list
    drifted: set
    detected_at: float
    actions: list = field(default_factory=list)
    skipped: list = field(default_factory=list)
    source: str = ""
    call_log: list = field(default_factory=list)
    applied: bool = False
    verified: Optional[bool] = None
    remediated_at: Optional[float] = None
    after: Optional[CloudState] = None
    notes: list = field(default_factory=list)


class Watcher:
    def __init__(self, provider, store: Store, auto_remediate: bool = False, max_actions: int = 5):
        self.provider, self.store = provider, store
        self.auto, self.max_actions = auto_remediate, max_actions
        self._last_fp = None

    async def cycle(self) -> CycleResult:
        state = await self.provider.fetch()
        detected_at = time.time()
        findings = evaluate(state)
        baseline = self.store.get_baseline()
        notes = []
        if baseline is None:
            if findings:
                notes.append("no baseline saved: current state already violates policy")
            else:
                self.store.set_baseline(state)
                self._last_fp = state.fingerprint()
                baseline = state
                notes.append("baseline captured")
        changes = diff_states(baseline, state) if baseline else []
        if state.fingerprint() != self._last_fp:
            self.store.save_snapshot(state, "auto")
            self._last_fp = state.fingerprint()
        res = CycleResult(state, findings, changes, drifted_resources(state, findings, changes),
                          detected_at, notes=notes)
        if not findings:
            return res

        self.store.log_event("drift_detected", {"findings": [f.id for f in findings]})
        res.actions, res.skipped = plan_remediation(findings, self.max_actions)
        if res.skipped:
            res.notes.append("%d action(s) exceed the per-cycle cap and need human review" % len(res.skipped))
        res.source = generate_source(res.actions)
        res.call_log = execute(res.source, self.provider.ec2, dry_run=not self.auto)
        res.applied = self.auto
        if self.auto:
            res.remediated_at = time.time()
            res.after = await self.provider.fetch()
            remaining = {f.id for f in evaluate(res.after)}
            targeted = {fid for a in res.actions for fid in a.finding_ids}
            res.verified = not (targeted & remaining)
            self.store.save_snapshot(res.after, "post-remediation")
            self._last_fp = res.after.fingerprint()
        self.store.log_event("remediation", {"applied": res.applied, "verified": res.verified,
                                             "calls": res.call_log})
        return res

    async def run(self, interval: float, stop: asyncio.Event, on_cycle=None):
        while not stop.is_set():
            res = await self.cycle()
            if on_cycle:
                on_cycle(res)
            try:
                await asyncio.wait_for(stop.wait(), interval)
            except asyncio.TimeoutError:
                pass
