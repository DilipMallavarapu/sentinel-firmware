#!/usr/bin/env python3
""" Wire the literature-derived detectors into the pipeline. Idempotent."""
import pathlib, sys

p = pathlib.Path("sentinel/firmware/pipeline.py")
if not p.is_file():
    print("run from the repo root"); sys.exit(1)
s = p.read_text()
if "backdoor" in s:
    print("already wired"); sys.exit(0)

anchor = "def stage_elfscan("
block = '''def stage_backdoor(run: RunState, cfg: dict) -> CheckpointResult:
    """
    Detectors derived from the published firmware corpus: authorized_keys,
    shipped TLS keypairs, build-environment leakage, and command-injection
    review ordering. See analyzers/backdoor.py for the sourcing.
    """
    from .analyzers.backdoor import DETECTORS as BACKDOOR_DETECTORS
    rfs: RootFS = run.config["_rootfs"]
    ctx = _ctx(run)
    findings: list[Finding] = []
    for det in BACKDOOR_DETECTORS:
        if det.applicable(rfs):
            findings.extend(det.run(rfs, ctx))
    n = _write_findings(run, "backdoor", findings)
    crit = sum(1 for f in findings if f.severity.value == "critical")
    return CheckpointResult(State.OK, outputs={"finding_count": n},
                            findings=n,
                            note=f"{n} findings, {crit} critical")


'''
s = s.replace(anchor, block + anchor, 1)
s = s.replace(
    '        Checkpoint("elfscan", "Scan binary hardening", stage_elfscan,',
    '        Checkpoint("backdoor", "Backdoor and hygiene checks", stage_backdoor,\n'
    '                   needs=["rootfs"]),\n'
    '        Checkpoint("elfscan", "Scan binary hardening", stage_elfscan,', 1)
s = s.replace('needs=["secrets", "elfscan", "services",',
              'needs=["secrets", "elfscan", "services", "backdoor",', 1)
s = s.replace('for stage in ("secrets", "elfscan", "services",',
              'for stage in ("secrets", "elfscan", "services", "backdoor",', 1)
p.write_text(s)
print("pipeline wired")

# scan_rootfs builds its own stage list
q = pathlib.Path("scan_rootfs.py")
if q.is_file():
    t = q.read_text()
    if "backdoor" not in t:
        t = t.replace(
            '        Checkpoint("elfscan", "Scan binary hardening", P.stage_elfscan,',
            '        Checkpoint("backdoor", "Backdoor and hygiene checks",\n'
            '                   P.stage_backdoor, needs=["rootfs"]),\n'
            '        Checkpoint("elfscan", "Scan binary hardening", P.stage_elfscan,', 1)
        t = t.replace('triage_needs = ["secrets", "elfscan", "services"]',
                      'triage_needs = ["secrets", "elfscan", "services", "backdoor"]', 1)
        q.write_text(t)
        print("scan_rootfs wired")
