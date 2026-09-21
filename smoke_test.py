"""
Smoke test: does the architecture actually enforce what it claims?

Three things under test, in order of importance:
  1. A finding cannot reach CONFIRMED without a proof that verifies.
  2. A tampered proof fails re-verification (so reports can be audited).
  3. The known-false-positive cases in the fixture stay out of CONFIRMED.
"""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sentinel.core import contracts  # noqa: E402
from sentinel.core import verifiers  # noqa: F401,E402  (registers verifiers)
from sentinel.core.contracts import (  # noqa: E402
    Axis, Confidence, Finding, ProofArtifact, RunContext, Scope, Severity,
    UnverifiableProof, verify_proof,
)
from sentinel.core.checkpoint import (  # noqa: E402
    Checkpoint, CheckpointResult, Pipeline, RunState, State,
)
from sentinel.firmware.analyzers.secrets import HardcodedCredentialDetector  # noqa: E402
from sentinel.firmware.analyzers.services import ServiceAnalyzer  # noqa: E402
from sentinel.firmware.models import RootFS  # noqa: E402
from sentinel.firmware.unpack import identify  # noqa: E402

HERE = Path(__file__).resolve().parent
FIXTURE = Path(os.environ.get("SENTINEL_FIXTURE", HERE / "fixture/rootfs"))
RUNDIR = HERE / "runs/smoke"
RUNDIR.mkdir(parents=True, exist_ok=True)

events = []
scope = Scope(authorization_ref="LOCAL-FIXTURE-001", domains=["localhost"])
ctx = RunContext(run_id="smoke", artifact_root=RUNDIR, scope=scope,
                 emit=lambda e, d: events.append((e, d)))

ok = True
def check(label, cond):
    global ok
    ok = ok and cond
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


print("\n== 1. CONFIRMED requires a verifying proof ==")
f = Finding(detector_id="t", title="t", severity=Severity.HIGH,
            axis=Axis.PRESENCE, target="etc/shadow")
check("new finding defaults to CANDIDATE", f.confidence == Confidence.CANDIDATE)

bogus = ProofArtifact(kind="byte_match",
                      claim={"blob": "nope", "file_sha256": "0"*64,
                             "offset": 0, "length": 1, "needle_sha256": "0"*64})
try:
    f.confirm(bogus, RUNDIR)
    check("confirm() rejects a proof that does not verify", False)
except UnverifiableProof:
    check("confirm() rejects a proof that does not verify", True)
check("finding stayed un-confirmed after the failed attempt",
      f.confidence == Confidence.CANDIDATE)

try:
    verify_proof(ProofArtifact(kind="made_up_kind", claim={}), RUNDIR)
    check("unknown proof kind is rejected", False)
except UnverifiableProof:
    check("unknown proof kind is rejected", True)


print("\n== 2. Credential detector on the fixture ==")
rfs = identify(RootFS(root=FIXTURE))
print(f"  identified: arch={rfs.arch} libc={rfs.libc} init={rfs.init_system}")
findings = list(HardcodedCredentialDetector().run(rfs, ctx))
for fd in sorted(findings, key=lambda x: x.target):
    print(f"    {fd.confidence.value:<9} {fd.severity.value:<8} {fd.target}"
          f"  ({fd.context.get('kind')})")

confirmed = [x for x in findings if x.confidence == Confidence.CONFIRMED]
targets = {x.target for x in confirmed}
check("root's real crypt hash in etc/shadow is CONFIRMED",
      "etc/shadow" in targets)
check("embedded private key is CONFIRMED", "etc/device_key.pem" in targets)
check("literal admin_password in lighttpd.conf is CONFIRMED",
      "etc/lighttpd.conf" in targets)
check("locked accounts (* and !) produced no finding",
      sum(1 for x in findings if x.target == "etc/shadow") == 1)
check("etc/passwd placeholder 'x' produced no finding",
      "etc/passwd" not in {x.target for x in findings})
check("README sample hash did NOT reach CONFIRMED",
      "docs/README.md" not in targets)
check("README hit is retained as CANDIDATE for review",
      any(x.target == "docs/README.md" and x.confidence == Confidence.CANDIDATE
          for x in findings))

# Regression cases taken from a real Tenda AC6 image, where the first run of
# this detector produced ~30 confirmed findings against HTML and JavaScript.
# The bytes were real; the claim "hardcoded credential" was not.
check("JavaScript in a web root produced NO finding",
      not any("main.html" in x.target for x in findings))
check("real secret in a .cfg beside that HTML IS confirmed",
      any(x.target.endswith("nvram_default.cfg")
          and x.confidence == Confidence.CONFIRMED for x in findings))
check("shell substitution $(nvram get pw) was not taken for a secret",
      not any("nvram" in str(x.context.get("details", "")) and "$(" in
              str(x.context.get("details", "")) for x in findings))
check("a passwd with three real accounts is ONE grouped finding",
      len([x for x in findings if x.target == "etc_ro/passwd"]) == 1)
check("that finding records all three accounts",
      any(x.target == "etc_ro/passwd" and x.context.get("occurrences") == 3
          for x in findings))

print("\n== 3. Proofs survive an audit, and tampering breaks them ==")
reverified = all(verify_proof(x.proof, RUNDIR) for x in confirmed)
check("every CONFIRMED proof re-verifies offline", reverified)

victim = confirmed[0]
tampered = ProofArtifact(kind=victim.proof.kind,
                         claim={**victim.proof.claim, "offset":
                                victim.proof.claim["offset"] + 1})
check("shifting the offset by one byte breaks the proof",
      verify_proof(tampered, RUNDIR) is False)

blob = RUNDIR / victim.proof.claim["blob"]
original = blob.read_bytes()
off = victim.proof.claim["offset"]
blob.write_bytes(original[:off] + bytes([original[off] ^ 0x01]) + original[off+1:])
check("editing the stored evidence breaks the proof",
      verify_proof(victim.proof, RUNDIR) is False)
blob.write_bytes(original)
check("restoring the evidence makes it verify again",
      verify_proof(victim.proof, RUNDIR) is True)


print("\n== 4. Service discovery ==")
an = ServiceAnalyzer()
services = an.discover(rfs)
svc_findings = list(an.findings(services, rfs, ctx))
print(f"  services: {[(s.name, s.port, s.runs_as) for s in services]}")
for sf in svc_findings:
    print(f"    {sf.confidence.value:<9} {sf.severity.value:<8} {sf.title}")
check("telnetd found", any(s.name == "telnetd" for s in services))
check("lighttpd found running as root",
      any(s.name == "lighttpd" and s.runs_as == "root" for s in services))
check("commented-out dropbear was not counted as autostart",
      not any(s.name == "dropbear" for s in services))
# Tenda and several MIPS SDKs keep init in /etc_ro, not /etc.
check("services under etc_ro/init.d are discovered",
      any(s.name == "httpd" for s in services))


print("\n== 5. Checkpoint engine: resume and blocking ==")
calls = []
pipe = Pipeline([
    Checkpoint("a", "Stage A", lambda r, c: (calls.append("a"),
               CheckpointResult(State.OK, outputs={"v": 1}))[1]),
    Checkpoint("b", "Stage B", lambda r, c: (calls.append("b"),
               CheckpointResult(State.FAILED, note="boom"))[1], needs=["a"]),
    Checkpoint("c", "Stage C", lambda r, c: (calls.append("c"),
               CheckpointResult(State.OK))[1], needs=["b"]),
    Checkpoint("d", "Stage D", lambda r, c: (calls.append("d"),
               CheckpointResult(State.OK))[1], needs=["a"]),
])
r1 = RunState(run_id="cp", root=RUNDIR / "cp", config={"k": 1})
r1.root.mkdir(parents=True, exist_ok=True)
pipe.run(r1)
check("failed stage blocks its dependent", r1.states["c"] == State.BLOCKED)
check("independent branch still runs", r1.states["d"] == State.OK)

calls.clear()
r2 = RunState(run_id="cp", root=RUNDIR / "cp", config={"k": 1})
pipe.run(r2)
check("successful stage is served from cache on resume",
      r2.states["a"] == State.CACHED and "a" not in calls)
check("failed stage is retried on resume", "b" in calls)

calls.clear()
r3 = RunState(run_id="cp", root=RUNDIR / "cp", config={"k": 2})
pipe.run(r3)
check("changing config invalidates the cache", "a" in calls)

print("\n" + ("ALL CHECKS PASSED" if ok else "FAILURES ABOVE"))
sys.exit(0 if ok else 1)
