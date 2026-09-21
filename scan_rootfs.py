#!/usr/bin/env python3
"""
Run the static lane against a rootfs you have already extracted.

    python3 scan_rootfs.py /path/to/extracted/rootfs --scope LOCAL-REVIEW

The full pipeline starts at a firmware image and works down. When you already
have the filesystem -- from an earlier binwalk run, a vendor SDK, a mounted
squashfs, a device you pulled the flash off -- `acquire` and `unpack` have
nothing to do and `unpack` will fail on a directory. This starts at `rootfs`
instead and runs everything downstream of it.

Emulation is off by default here. Turn it on with --emulate once you have a
static qemu-user and are running somewhere you are willing to execute vendor
binaries.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.core.checkpoint import (  # noqa: E402
    Checkpoint, CheckpointResult, Pipeline, RunState, State,
)
from sentinel.core.contracts import Scope  # noqa: E402
from sentinel.firmware import pipeline as P  # noqa: E402
from sentinel.firmware.models import RootFS  # noqa: E402
from sentinel.firmware.unpack import identify  # noqa: E402


def stage_rootfs_direct(run: RunState, cfg: dict) -> CheckpointResult:
    """Stands in for acquire+unpack+rootfs when the filesystem is already on disk."""
    root = Path(cfg["rootfs_path"]).resolve()
    if not root.is_dir():
        return CheckpointResult(State.FAILED, note=f"{root} is not a directory")

    rfs = identify(RootFS(root=root))
    run.config["_rootfs"] = rfs
    files = sum(1 for _ in rfs.walk())

    # Worth flagging rather than silently proceeding: a "rootfs" with no
    # /etc and no /bin is usually a fragment from a partial extraction, and
    # scanning it produces a clean report that means nothing.
    shape = [d for d in ("etc", "bin", "sbin", "usr", "lib")
             if (root / d).is_dir()]
    note = f"{rfs.arch or 'arch?'}/{rfs.libc or 'libc?'}, {files} files"
    if len(shape) < 2:
        found = ", ".join(shape) if shape else "none"
        note += (f" -- top-level dirs found: {found}; this looks like an "
                 f"extraction fragment, not a root filesystem")

    return CheckpointResult(State.OK, outputs={
        "root": str(root), "arch": rfs.arch, "endian": rfs.endian,
        "libc": rfs.libc, "init": rfs.init_system, "files": files,
        "top_level": shape,
    }, note=note)


def build(emulate: bool) -> Pipeline:
    stages = [
        Checkpoint("rootfs", "Read the extracted filesystem", stage_rootfs_direct),
        Checkpoint("services", "Find services started at boot", P.stage_services,
                   needs=["rootfs"]),
        Checkpoint("secrets", "Search for credentials and keys", P.stage_secrets,
                   needs=["rootfs"]),
        Checkpoint("elfscan", "Scan binary hardening", P.stage_elfscan,
                   needs=["rootfs", "services"], optional=True),
    ]
    triage_needs = ["secrets", "elfscan", "services"]
    if emulate:
        stages += [
            Checkpoint("emulate", "Stage for user-mode emulation", P.stage_emulate,
                       needs=["rootfs", "services"], optional=True),
            Checkpoint("reachability", "Exercise CGI handlers",
                       P.stage_reachability, needs=["emulate"], optional=True,
                       gate=lambda run: bool(run.out("emulate", "base_url"))),
        ]
        triage_needs.append("reachability")
    stages += [
        Checkpoint("triage", "Dedupe and verify findings", P.stage_triage,
                   needs=triage_needs),
        Checkpoint("report", "Write the report", P.stage_report, needs=["triage"]),
    ]
    return Pipeline(stages)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("rootfs")
    ap.add_argument("--scope", default="LOCAL-REVIEW",
                    help="authorization reference for the report")
    ap.add_argument("--workdir", default="runs")
    ap.add_argument("--bin-dir", default="bin")
    ap.add_argument("--emulate", action="store_true",
                    help="also stage and exercise CGI binaries under qemu-user")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    run_id = uuid.uuid4().hex[:12]
    root = Path(args.workdir) / run_id
    root.mkdir(parents=True, exist_ok=True)

    def emit(event: str, data: dict) -> None:
        if args.quiet:
            return
        if event == "checkpoint.state":
            print(f"  [{data.get('state','?'):<8}] {data.get('id',''):<13} "
                  f"{data.get('note','')}")
        elif event == "coverage":
            print(f"  [coverage] {data.get('unparsed')} files unparseable: "
                  f"{data.get('note')}")
        elif event == "policy":
            print(f"  [policy]   {data.get('rule')}")

    run = RunState(
        run_id=run_id, root=root,
        config={"rootfs_path": args.rootfs, "bin_dir": args.bin_dir,
                "_scope": Scope(authorization_ref=args.scope),
                "emulation_backend": "qemu-user" if args.emulate else None},
        emit=emit,
    )
    build(args.emulate).run(run)

    report = root / "report.json"
    if not report.is_file():
        print("\nno report written; the run failed early", file=sys.stderr)
        return 1

    findings = json.loads(report.read_text())["findings"]
    tiers: dict[str, int] = {}
    for f in findings:
        tiers[f["confidence"]] = tiers.get(f["confidence"], 0) + 1

    print(f"\n{report}")
    for tier in ("confirmed", "probable", "candidate"):
        rows = [f for f in findings if f["confidence"] == tier]
        if not rows:
            continue
        print(f"\n{tier} ({len(rows)}):")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for f in sorted(rows, key=lambda x: order.get(x["severity"], 9))[:25]:
            print(f"  {f['severity']:<8} {f['axis']:<12} {f['target']}")
            print(f"           {f['title']}")
        if len(rows) > 25:
            print(f"  … {len(rows) - 25} more in the report")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
