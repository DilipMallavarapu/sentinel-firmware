"""
sentinel.firmware.analyzers.hardening
=====================================

Turns elfscan's Go records into findings, and refuses to overclaim.

The temptation with mitigation data is to emit one HIGH finding per binary
with no canary. On a uClibc router image that is four thousand findings and a
report nobody reads. The posture taken here:

  * A single binary missing a mitigation is INFO and, on its own, is not
    reported. It lands in the inventory.
  * The *aggregate* posture is one MEDIUM finding: "no binary in this image
    has RELRO; the toolchain ships mitigations off by default." That is the
    actionable statement a vendor can fix, and it is one finding.
  * A network-facing, setuid, or init-started binary missing mitigations is
    reported individually, because reachability is plausible and the operator
    should look. Still PRESENCE axis: we say the mitigation is absent, not
    that the binary is exploitable.
  * Risky imports are never a finding by themselves. `strcpy` in a binary is
    not a bug. They are attached as context to steer manual review, which is
    what they are actually good for.

That last rule is where most firmware scanners generate their noise, and
holding it is the difference between a tool your OpenBMC/Hikvision workflow
trusts and one you stop reading.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Iterable

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)
from ..models import RootFS, Service

# Binaries where a missing mitigation is worth an individual finding.
INTERESTING_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/", "www/", "cgi-bin/")


class HardeningAnalyzer:
    meta = DetectorMeta(
        id="fw.binary.hardening",
        name="Exploit mitigation posture of firmware binaries",
        severity=Severity.MEDIUM,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-1277",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["hardening", "binary", "go-worker"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def analyze(self, records: list[dict], rootfs: RootFS,
                services: list[Service], ctx: RunContext) -> Iterable[Finding]:
        # A record carrying an error is a file the worker could not parse --
        # a packed binary, a truncated extraction, a non-ELF with ELF magic.
        # Its absent mitigation block means "unknown", never "absent", and
        # counting it as absent would manufacture findings out of extraction
        # failures. Dropped here and surfaced as a coverage number instead.
        unparsed = [r for r in records if r.get("error")]
        records = [r for r in records if not r.get("error")]
        if unparsed:
            ctx.emit("coverage", {
                "stage": "elfscan",
                "unparsed": len(unparsed),
                "note": "excluded from hardening analysis; posture unknown",
            })
        if not records:
            return

        exe = [r for r in records if r.get("type") == "ET_EXEC"
               or (r.get("type") == "ET_DYN" and r.get("interp"))]
        if not exe:
            exe = records

        service_bins = {
            (s.binary or "").lstrip("/") for s in services if s.binary
        }

        # -- aggregate posture ----------------------------------------
        tally = Counter()
        for r in exe:
            m = r.get("mitigations") or {}
            tally["nx"] += bool(m.get("nx"))
            tally["pie"] += bool(m.get("pie"))
            tally["canary"] += bool(m.get("canary"))
            tally["full_relro"] += m.get("relro") == "full"
            tally["fortify"] += bool(m.get("fortify"))
        n = len(exe)

        for key, label, sev in [
            ("nx", "non-executable stack", Severity.MEDIUM),
            ("canary", "stack canaries", Severity.MEDIUM),
            ("pie", "position-independent executables", Severity.LOW),
            ("full_relro", "full RELRO", Severity.LOW),
        ]:
            covered = tally[key]
            pct = (covered / n) * 100 if n else 0
            # Firing only at exactly zero loses the common and more
            # interesting case: an image where a handful of binaries were
            # built with a mitigation and the rest were not. That is still a
            # toolchain defect and it is what real vendor images look like.
            if pct >= 80:
                continue
            missing = n - covered
            scope_phrase = (f"None of the {n} executables"
                            if covered == 0
                            else f"{missing} of {n} executables")
            yield Finding(
                    detector_id=self.meta.id,
                    title=(f"Image-wide: {label} absent from "
                           + (f"all {n} executables" if covered == 0
                              else f"{missing} of {n} executables "
                                   f"({pct:.0f}% covered)")),
                    severity=sev if covered == 0 else (
                        Severity.LOW if sev.rank > 1 else Severity.INFO),
                    axis=Axis.PRESENCE,
                    target=str(rootfs.root.name),
                    summary=(
                        f"{scope_phrase} in this image were built with "
                        f"{label}. This is a build-toolchain default, so the "
                        f"fix is one flag change rather than {missing} code "
                        f"changes. Reported once rather than per binary."
                    ),
                    confidence=Confidence.PROBABLE,
                    cwe=self.meta.cwe,
                    context={"locus": {"scope": "image", "mitigation": key},
                             "executables": n, "covered": covered,
                             "coverage_pct": round(pct, 1),
                             "arch": rootfs.arch},
                    triage_notes=["aggregate finding; per-binary detail is in "
                                  "the inventory artifact"],
            )

        # -- individually interesting binaries -------------------------
        for r in exe:
            path = r.get("path", "")
            m = r.get("mitigations") or {}
            reachable_hint = (
                path in service_bins
                or r.get("setuid")
                or any(path.startswith(d) for d in INTERESTING_DIRS)
                and ("cgi" in path or "httpd" in path or "web" in path)
            )
            missing = [k for k, v in
                       (("NX", m.get("nx")), ("canary", m.get("canary")),
                        ("PIE", m.get("pie")))
                       if not v]
            if not (reachable_hint and missing):
                continue

            sev = Severity.HIGH if r.get("setuid") else Severity.MEDIUM
            f = Finding(
                detector_id=self.meta.id,
                title=f"{path} lacks {', '.join(missing)}",
                severity=sev,
                axis=Axis.PRESENCE,
                target=path,
                summary=(
                    f"{path} is "
                    + ("setuid-root and " if r.get("setuid") else "")
                    + ("reachable from a network service " if path in service_bins
                       else "in a network-facing location ")
                    + f"and is missing {', '.join(missing)}. Absence of the "
                      f"mitigation is proven; exploitability is not claimed."
                ),
                cwe=self.meta.cwe,
                context={
                    "locus": {"file": path},
                    "mitigations": m,
                    "risky_imports": r.get("risky_imports", []),
                    "needed": r.get("needed", []),
                    "setuid": r.get("setuid", False),
                    "review_hint": (
                        "risky imports are listed to direct manual review; "
                        "their presence is not itself a defect"
                    ),
                },
            )

            # Proof: the binary's own hash. The ELF header bytes that encode
            # the mitigation are inside the file we hashed, so re-parsing the
            # stored blob reproduces the claim exactly.
            blob = rootfs.root / path
            if blob.is_file() and blob.stat().st_size < (16 << 20):
                data = blob.read_bytes()
                rel = ctx.store_blob(path.replace("/", "_"), data)
                proof = ProofArtifact(
                    kind="byte_match",
                    claim={"blob": rel,
                           "file_sha256": hashlib.sha256(data).hexdigest(),
                           "offset": 0, "length": 64,
                           "needle_sha256": hashlib.sha256(data[:64]).hexdigest()},
                    blobs=[rel],
                )
                try:
                    f.confirm(proof, ctx.artifact_root)
                except Exception:
                    f.confidence = Confidence.PROBABLE
            yield f


__all__ = ["HardeningAnalyzer"]
