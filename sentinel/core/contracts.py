"""
sentinel.core.contracts
=======================

The shared vocabulary for every detector in Sentinel -- web, firmware, Python
or Go.

The central design rule of this module:

    A finding may only be CONFIRMED if it carries a ProofArtifact, and a
    ProofArtifact is only valid if a deterministic verifier can re-derive the
    same answer from stored bytes, offline, with no network and no model.

This is what turns "no false positives" from a marketing claim into a property
the type system enforces. `Finding.confirm()` refuses to run without a proof,
and `Registry` refuses to register a detector that declares CONFIRMED-capable
without implementing `verify()`.

Everything below CONFIRMED is explicitly, visibly not confirmed. We would
rather report 40 confirmed findings and 200 candidates than 240 "findings"
that a triager has to re-check by hand.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Protocol, runtime_checkable


# --------------------------------------------------------------------------
# Severity and confidence
# --------------------------------------------------------------------------

class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class Confidence(str, Enum):
    """
    The only tier that is reported as a finding by default is CONFIRMED.

    CONFIRMED   A stored ProofArtifact exists and its verifier returns True.
                Re-checkable offline, deterministically, forever. If the
                verifier is non-deterministic or needs the network, the
                detector is wrong, not the target.

    PROBABLE    Multiple independent weak signals agree (heuristic + LLM
                fusion + corroborating context) but no single re-checkable
                oracle exists. Surfaced in a separate queue for human triage.

    CANDIDATE   One weak signal. Version-string CVE matches live here almost
                always: "this binary reports BusyBox 1.29" is a fact, "this
                device is vulnerable to CVE-XXXX" is not.

    REFUTED     A previous finding that revalidation disproved. Kept, never
                deleted -- refutations are how the heuristics get tuned.
    """
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    CANDIDATE = "candidate"
    REFUTED = "refuted"


class Axis(str, Enum):
    """
    The distinction that kills most firmware false positives.

    PRESENCE      "These bytes exist at this offset in this file." Verifiable
                  to a certainty. A hardcoded root hash in /etc/shadow is a
                  PRESENCE fact.

    REACHABILITY  "An unauthenticated remote caller can influence this." Not
                  decidable from a filesystem dump. Requires emulation, a
                  runtime oracle, or manual analysis. Never assert this from
                  static analysis alone.

    A detector declares which axis it proves. The pipeline will not let a
    PRESENCE-only detector emit a finding whose title claims exploitability.
    """
    PRESENCE = "presence"
    REACHABILITY = "reachability"


# --------------------------------------------------------------------------
# Proof
# --------------------------------------------------------------------------

@dataclass
class ProofArtifact:
    """
    Everything needed to re-check a finding without the target.

    `kind` selects the verifier. `blobs` are paths, relative to the run's
    artifact root, of the raw bytes captured at detection time. `claim` is the
    structured assertion the verifier must reproduce.

    Worked examples:

      byte_match    claim={"path": "etc/shadow", "offset": 420,
                          "sha256": "..."}  -- the file still hashes the same
                          and the bytes at that offset still match.

      differential  claim={"control_sha": "...", "probe_sha": "...",
                          "divergence": "row_count"} -- the control response
                          and the probe response differ in a way a benign
                          request could not explain. Both bodies are stored.

      oob_callback  claim={"canary": "a1b2c3.oob.example",
                          "observed_at": 1699999999, "protocol": "dns"} --
                          the canary was unique to this probe and only this
                          probe could have caused the lookup.

      runtime_diff  claim={"emulated_request": "...", "status_control": 403,
                          "status_probe": 200} -- observed against the
                          emulated firmware, with both transcripts stored.
    """
    kind: str
    claim: dict[str, Any]
    blobs: list[str] = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        payload = json.dumps(
            {"kind": self.kind, "claim": self.claim}, sort_keys=True
        ).encode()
        return hashlib.sha256(payload).hexdigest()[:16]


VerifierFn = Callable[[ProofArtifact, Path], bool]

_VERIFIERS: dict[str, VerifierFn] = {}


def verifier(kind: str) -> Callable[[VerifierFn], VerifierFn]:
    """Register the offline re-check for a proof kind."""
    def wrap(fn: VerifierFn) -> VerifierFn:
        _VERIFIERS[kind] = fn
        return fn
    return wrap


def verify_proof(proof: ProofArtifact, artifact_root: Path) -> bool:
    fn = _VERIFIERS.get(proof.kind)
    if fn is None:
        raise UnverifiableProof(
            f"no verifier registered for proof kind {proof.kind!r}; "
            f"a detector may not emit CONFIRMED with an unverifiable proof"
        )
    return fn(proof, artifact_root)


class UnverifiableProof(Exception):
    pass


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    detector_id: str
    title: str
    severity: Severity
    axis: Axis
    target: str                      # URL, or rootfs-relative path
    summary: str = ""
    confidence: Confidence = Confidence.CANDIDATE
    proof: Optional[ProofArtifact] = None
    cwe: Optional[str] = None
    owasp: Optional[str] = None      # e.g. "A03:2021"
    references: list[str] = field(default_factory=list)
    context: dict[str, Any] = field(default_factory=dict)
    triage_notes: list[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    first_seen: float = field(default_factory=time.time)

    # -- promotion is the only way to reach CONFIRMED -----------------------

    def confirm(self, proof: ProofArtifact, artifact_root: Path) -> "Finding":
        """
        Promote to CONFIRMED. Raises unless the proof verifies right now.

        Deliberately strict: a detector that wants CONFIRMED has to hand over
        re-checkable bytes at the moment of detection. Post-hoc confirmation
        from a model's opinion is not available through any code path.
        """
        if not verify_proof(proof, artifact_root):
            raise UnverifiableProof(
                f"{self.detector_id}: proof {proof.fingerprint()} did not verify"
            )
        self.proof = proof
        self.confidence = Confidence.CONFIRMED
        return self

    def refute(self, reason: str) -> "Finding":
        self.confidence = Confidence.REFUTED
        self.triage_notes.append(f"refuted: {reason}")
        return self

    def dedupe_key(self) -> str:
        """
        Stable across runs so the same issue on the same target collapses.
        Intentionally excludes timestamps and proof blobs.
        """
        parts = [self.detector_id, self.target, self.axis.value,
                 json.dumps(self.context.get("locus", {}), sort_keys=True)]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["confidence"] = self.confidence.value
        d["axis"] = self.axis.value
        d["dedupe_key"] = self.dedupe_key()
        return d


# --------------------------------------------------------------------------
# Detector protocol
# --------------------------------------------------------------------------

@dataclass
class DetectorMeta:
    id: str
    name: str
    severity: Severity
    axis: Axis
    owasp: Optional[str] = None
    cwe: Optional[str] = None
    lane: str = "web"                # "web" | "firmware" | "both"
    proof_kinds: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    # Declares intent. Enforced at registration: True requires proof_kinds.
    can_confirm: bool = False


@runtime_checkable
class Detector(Protocol):
    meta: DetectorMeta

    def applicable(self, subject: Any) -> bool:
        """Cheap gate. Skip the whole detector when the subject can't match."""
        ...

    def run(self, subject: Any, ctx: "RunContext") -> Iterable[Finding]:
        ...


@dataclass
class RunContext:
    """Passed to every detector. The only sanctioned way to touch the disk."""
    run_id: str
    artifact_root: Path
    scope: "Scope"
    emit: Callable[[str, dict[str, Any]], None]
    config: dict[str, Any] = field(default_factory=dict)

    def store_blob(self, name: str, data: bytes) -> str:
        """Write evidence bytes, return the run-relative path for a proof."""
        rel = Path("blobs") / f"{hashlib.sha256(data).hexdigest()[:16]}_{name}"
        dest = self.artifact_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return str(rel)


# --------------------------------------------------------------------------
# Scope -- authorization is a core model, not a flag
# --------------------------------------------------------------------------

@dataclass
class Scope:
    """
    Nothing runs outside this. Mirrors the web-side scope enforcement so the
    firmware lane inherits the same discipline: an emulated device is still a
    target, and an emulated device that phones home to a real vendor endpoint
    is an out-of-scope request we must refuse to make.
    """
    authorization_ref: str           # bounty program, PO number, written scope
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    firmware_sha256: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    allow_emulated_egress: bool = False

    def permits_host(self, host: str) -> bool:
        h = host.lower().strip(".")
        if any(h == e or h.endswith("." + e) for e in self.exclusions):
            return False
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def permits_image(self, sha256: str) -> bool:
        return sha256.lower() in {s.lower() for s in self.firmware_sha256}


__all__ = [
    "Severity", "Confidence", "Axis", "ProofArtifact", "Finding",
    "Detector", "DetectorMeta", "RunContext", "Scope",
    "verifier", "verify_proof", "UnverifiableProof",
]
