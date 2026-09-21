"""
sentinel.core.goworker
======================

The bridge that makes Go binaries first-class detectors.

Protocol, deliberately boring:
    stdin   one JSON request
    stdout  newline-delimited JSON records, terminated by {"_done": true,...}
    stderr  diagnostics, surfaced on failure, never parsed
    exit 0  findings are not errors

Why a subprocess and not cgo/gRPC: a worker that speaks JSONL over a pipe can
be tested with `echo '{...}' | ./elfscan`, swapped for a shell script during
development, and run on a different host with no code change. The coupling is
one line of schema. gRPC would buy streaming we do not need and cost a build
dependency on every dev machine.

Records are streamed and dispatched as they arrive, so a 40,000-file rootfs
starts producing dashboard events in the first second rather than after the
whole walk completes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterator


class GoWorkerError(RuntimeError):
    pass


class GoWorker:
    def __init__(self, name: str, binary: str | Path | None = None,
                 search_paths: list[Path] | None = None):
        self.name = name
        self.binary = self._resolve(name, binary, search_paths or [])

    @staticmethod
    def _resolve(name: str, binary: str | Path | None,
                 search_paths: list[Path]) -> Path | None:
        if binary:
            p = Path(binary)
            return p if p.is_file() and os.access(p, os.X_OK) else None
        for base in [*search_paths, Path("bin"), Path("go/bin"), Path.cwd() / "bin"]:
            cand = base / name
            if cand.is_file() and os.access(cand, os.X_OK):
                return cand
        found = shutil.which(name)
        return Path(found) if found else None

    @property
    def available(self) -> bool:
        return self.binary is not None

    def stream(self, request: dict[str, Any], timeout: int = 900
               ) -> Iterator[dict[str, Any]]:
        """
        Yield records as the worker emits them. The final summary record
        (`_done`) is yielded too, so callers can assert the worker finished
        rather than died halfway -- a truncated stream that looks like a clean
        result is exactly the failure mode that produces false negatives.
        """
        if not self.available:
            raise GoWorkerError(
                f"go worker {self.name!r} not found. Build it with: "
                f"go build -o bin/{self.name} ./go/{self.name}"
            )

        proc = subprocess.Popen(
            [str(self.binary)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        deadline = time.time() + timeout
        saw_done = False
        try:
            assert proc.stdin and proc.stdout
            proc.stdin.write(json.dumps(request))
            proc.stdin.close()

            for line in proc.stdout:
                if time.time() > deadline:
                    proc.kill()
                    raise GoWorkerError(f"{self.name}: timed out after {timeout}s")
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue      # a stray print is not fatal
                if rec.get("_done"):
                    saw_done = True
                yield rec
        finally:
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()

        if proc.returncode not in (0, None):
            err = (proc.stderr.read() if proc.stderr else "")[-2000:]
            raise GoWorkerError(f"{self.name} exited {proc.returncode}: {err}")
        if not saw_done:
            raise GoWorkerError(
                f"{self.name}: stream ended without a completion record; "
                f"results are incomplete and will not be trusted"
            )

    def collect(self, request: dict[str, Any], timeout: int = 900
                ) -> tuple[list[dict], dict]:
        records, summary = [], {}
        for rec in self.stream(request, timeout):
            (summary.update(rec) if rec.get("_done") else records.append(rec))
        return records, summary

    def each(self, request: dict[str, Any],
             on_record: Callable[[dict], None], timeout: int = 900) -> dict:
        summary: dict = {}
        for rec in self.stream(request, timeout):
            if rec.get("_done"):
                summary = rec
            else:
                on_record(rec)
        return summary


__all__ = ["GoWorker", "GoWorkerError"]
