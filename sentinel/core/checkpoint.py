"""
sentinel.core.checkpoint
========================

The execution spine. A run is a DAG of checkpoints; each one is pure with
respect to its declared inputs, writes its outputs to the run directory, and
emits SSE events the dashboard renders live.

Why checkpoints rather than a linear scan loop:

  * Firmware runs are long. Unpacking a 64MB image, walking 40k files and
    booting an emulator is minutes-to-hours. A crash at the emulation stage
    must not throw away the unpack.
  * Every stage's output is evidence. Checkpoint dirs *are* the artifact
    store, so a report can cite "stage unpack, artifact rootfs/etc/shadow".
  * The UI the user asked for is a view of this DAG. Nodes are checkpoints,
    edges are `needs`, and each node exposes its artifacts for inspection.
  * Agents plan by rewriting the DAG, not by improvising control flow. A
    planner agent adds checkpoints; it never gets to call subprocesses.

Resume semantics: a checkpoint is skipped when its state file says `ok` and
its input fingerprint is unchanged. Change the image, a config key, or the
code version of the stage, and it re-runs. Nothing silently reuses stale work.
"""

from __future__ import annotations

import hashlib
import json
import time
import traceback
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


class State(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"      # gate said not applicable (e.g. no ELF binaries)
    CACHED = "cached"        # resumed from a previous run
    BLOCKED = "blocked"      # an upstream checkpoint failed


@dataclass
class CheckpointResult:
    state: State
    outputs: dict[str, Any] = field(default_factory=dict)
    findings: int = 0
    note: str = ""


StageFn = Callable[["RunState", dict[str, Any]], CheckpointResult]


@dataclass
class Checkpoint:
    id: str
    label: str                       # what the UI shows a human
    fn: StageFn
    needs: list[str] = field(default_factory=list)
    # Bumped when the stage's logic changes, to invalidate cached results.
    version: str = "1"
    # A stage may be gated off by inspecting upstream outputs.
    gate: Optional[Callable[["RunState"], bool]] = None
    optional: bool = False           # failure does not block downstream


# --------------------------------------------------------------------------

@dataclass
class RunState:
    run_id: str
    root: Path
    config: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, dict[str, Any]] = field(default_factory=dict)
    states: dict[str, State] = field(default_factory=dict)
    emit: Callable[[str, dict], None] = lambda e, d: None

    def dir(self, checkpoint_id: str) -> Path:
        d = self.root / "stages" / checkpoint_id
        d.mkdir(parents=True, exist_ok=True)
        return d

    def out(self, checkpoint_id: str, key: str, default=None):
        return self.outputs.get(checkpoint_id, {}).get(key, default)


class Pipeline:
    def __init__(self, checkpoints: list[Checkpoint]):
        self.checkpoints = {c.id: c for c in checkpoints}
        self._order = self._toposort()

    def _toposort(self) -> list[str]:
        seen, order, marks = set(), [], {}

        def visit(cid: str, stack: tuple[str, ...]):
            if marks.get(cid) == "done":
                return
            if cid in stack:
                raise ValueError(f"cycle in pipeline: {' -> '.join(stack + (cid,))}")
            for dep in self.checkpoints[cid].needs:
                if dep not in self.checkpoints:
                    raise ValueError(f"{cid} needs unknown checkpoint {dep!r}")
                visit(dep, stack + (cid,))
            marks[cid] = "done"
            if cid not in seen:
                seen.add(cid)
                order.append(cid)

        for cid in self.checkpoints:
            visit(cid, ())
        return order

    # -- fingerprinting -----------------------------------------------------

    def _fingerprint(self, cp: Checkpoint, run: RunState) -> str:
        payload = {
            "version": cp.version,
            "config": {k: run.config[k] for k in sorted(run.config)
                       if not k.startswith("_")},
            "upstream": {d: run.outputs.get(d, {}).get("_fingerprint")
                         for d in sorted(cp.needs)},
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()[:16]

    def _load_cached(self, cp: Checkpoint, run: RunState, fp: str):
        f = run.dir(cp.id) / "_state.json"
        if not f.is_file():
            return None
        try:
            saved = json.loads(f.read_text())
        except Exception:
            return None
        if saved.get("state") != State.OK.value or saved.get("fingerprint") != fp:
            return None
        return saved

    def _save(self, cp: Checkpoint, run: RunState, fp: str,
              res: CheckpointResult, elapsed: float) -> None:
        (run.dir(cp.id) / "_state.json").write_text(json.dumps({
            "checkpoint": cp.id,
            "state": res.state.value,
            "fingerprint": fp,
            "outputs": res.outputs,
            "findings": res.findings,
            "note": res.note,
            "elapsed": round(elapsed, 3),
            "finished_at": time.time(),
        }, indent=2, default=str))

    # -- execution ----------------------------------------------------------

    def plan(self) -> list[dict]:
        """The DAG, for the UI to render before anything runs."""
        return [{
            "id": c.id, "label": c.label, "needs": c.needs,
            "optional": c.optional, "state": State.PENDING.value,
        } for c in (self.checkpoints[i] for i in self._order)]

    def run(self, run: RunState, resume: bool = True) -> RunState:
        run.emit("run.start", {"run_id": run.run_id, "plan": self.plan()})

        for cid in self._order:
            cp = self.checkpoints[cid]

            blocked = [d for d in cp.needs
                       if run.states.get(d) in (State.FAILED, State.BLOCKED)
                       and not self.checkpoints[d].optional]
            if blocked:
                run.states[cid] = State.BLOCKED
                run.emit("checkpoint.state", {"id": cid, "state": "blocked",
                                              "note": f"upstream {blocked[0]} failed"})
                continue

            if cp.gate is not None and not cp.gate(run):
                run.states[cid] = State.SKIPPED
                run.outputs.setdefault(cid, {})
                run.emit("checkpoint.state", {"id": cid, "state": "skipped",
                                              "note": "not applicable to this target"})
                continue

            fp = self._fingerprint(cp, run)

            if resume:
                cached = self._load_cached(cp, run, fp)
                if cached:
                    run.states[cid] = State.CACHED
                    run.outputs[cid] = dict(cached["outputs"], _fingerprint=fp)
                    run.emit("checkpoint.state", {
                        "id": cid, "state": "cached",
                        "findings": cached.get("findings", 0),
                        "note": "unchanged since last run",
                    })
                    continue

            run.states[cid] = State.RUNNING
            run.emit("checkpoint.state", {"id": cid, "state": "running",
                                          "label": cp.label})
            t0 = time.time()
            try:
                res = cp.fn(run, run.config)
            except Exception as exc:
                elapsed = time.time() - t0
                (run.dir(cid) / "_error.txt").write_text(traceback.format_exc())
                res = CheckpointResult(State.FAILED, note=f"{type(exc).__name__}: {exc}")
                run.states[cid] = State.FAILED
                run.outputs[cid] = {"_fingerprint": fp}
                self._save(cp, run, fp, res, elapsed)
                run.emit("checkpoint.state", {"id": cid, "state": "failed",
                                              "note": res.note,
                                              "elapsed": round(elapsed, 2)})
                if cp.optional:
                    continue
                # Non-optional failure does not abort the run: independent
                # branches still have value. Downstream gets BLOCKED above.
                continue

            elapsed = time.time() - t0
            run.states[cid] = res.state
            run.outputs[cid] = dict(res.outputs, _fingerprint=fp)
            self._save(cp, run, fp, res, elapsed)
            run.emit("checkpoint.state", {
                "id": cid, "state": res.state.value, "findings": res.findings,
                "note": res.note, "elapsed": round(elapsed, 2),
            })

        summary = {
            "run_id": run.run_id,
            "states": {k: v.value for k, v in run.states.items()},
            "findings": sum(
                (run.outputs.get(c, {}) or {}).get("finding_count", 0)
                for c in self.checkpoints
            ),
        }
        (run.root / "run.json").write_text(json.dumps(summary, indent=2))
        run.emit("run.end", summary)
        return run


__all__ = ["Pipeline", "Checkpoint", "CheckpointResult", "RunState", "State"]
