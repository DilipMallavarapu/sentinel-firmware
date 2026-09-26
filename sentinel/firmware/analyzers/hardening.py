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


def _canary_state(rec: dict) -> str:
    """Normalize the worker's canary verdict to present|absent|unknown.

    New worker output is already one of those three strings. Records from
    before the three-state change stored a bool; a bare True is honestly
    "present", but a bare False is *not* honestly "absent" -- that was the
    exact false-negative we are fixing -- so it maps to "unknown" here rather
    than silently re-asserting the old lie against stale data.
    """
    v = (rec.get("mitigations") or {}).get("canary")
    if v in ("present", "absent", "unknown"):
        return v
    if v is True:
        return "present"
    return "unknown"


def _build_canary_proof(rec: dict, rootfs: "RootFS", ctx: "RunContext"):
    """Build a symbol_presence proof that re-derives the canary verdict from
    the exact bytes searched -- the string table region for present/absent, or
    the ELF header + program headers for unknown. Returns None when the
    evidence cannot be captured (e.g. the derived-not-raw symtab-section path,
    where there is no raw file region to store)."""
    ev = rec.get("sym_evidence") or {}
    src = ev.get("source")
    path = rec.get("path", "")
    fp = rootfs.root / path
    if not fp.is_file():
        return None
    state = _canary_state(rec)

    if src == "dynamic-strtab" and int(ev.get("strtab_len", 0)) > 0:
        off, ln = int(ev["strtab_off"]), int(ev["strtab_len"])
        try:
            with open(fp, "rb") as fh:
                fh.seek(off)
                region = fh.read(ln)
        except OSError:
            return None
        if len(region) != ln:
            return None
        rel = ctx.store_blob(f"{path.replace('/', '_')}.dynstr", region)
        claim = {"blob": rel, "region_sha256": hashlib.sha256(region).hexdigest(),
                 "result": state, "needle": "stack_chk", "region_file_offset": off}
        if state == "present":
            claim["match_off_in_region"] = int(ev.get("canary_off", 0)) - off
        return ProofArtifact(kind="symbol_presence", claim=claim, blobs=[rel])

    if src == "none" and state == "unknown":
        # The unknown verdict is "no symbol section and no readable dynstr",
        # which can only be re-derived by walking the section and program
        # header tables -- so the evidence is the whole ELF. Bounded: a
        # statically linked, stripped helper (the case that lands here) is
        # small; anything over the cap is left PROBABLE rather than storing a
        # partial file the verifier could not trust.
        try:
            size = fp.stat().st_size
        except OSError:
            return None
        if size > (8 << 20):
            return None
        try:
            data = fp.read_bytes()
        except OSError:
            return None
        rel = ctx.store_blob(f"{path.replace('/', '_')}.elf", data)
        return ProofArtifact(
            kind="symbol_presence",
            claim={"blob": rel, "region_sha256": hashlib.sha256(data).hexdigest(),
                   "result": "unknown", "reason": ev.get("reason", "")},
            blobs=[rel])
    return None


class HardeningAnalyzer:
    meta = DetectorMeta(
        id="fw.binary.hardening",
        name="Exploit mitigation posture of firmware binaries",
        severity=Severity.MEDIUM,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-1277",
        proof_kinds=["byte_match", "symbol_presence"],
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

        n = len(exe)

        # -- aggregate posture: phdr-derived mitigations --------------
        # NX/PIE/RELRO come from the program headers and the dynamic segment,
        # both of which survive section stripping, so these are always a clean
        # two-valued present/absent count.
        tally = Counter()
        for r in exe:
            m = r.get("mitigations") or {}
            tally["nx"] += bool(m.get("nx"))
            tally["pie"] += bool(m.get("pie"))
            tally["full_relro"] += m.get("relro") == "full"

        for key, label, sev in [
            ("nx", "non-executable stack", Severity.MEDIUM),
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

        # -- aggregate posture: canaries (three-state, with a denominator) --
        # Canaries are symbol-derived, so an unreadable symbol table means we
        # could not measure -- not that the mitigation is absent. Every number
        # below therefore carries the population it was computed over. The
        # coverage percentage is taken over *measured* binaries only; folding
        # the unknowns into the denominator would understate coverage exactly
        # the way the old symbol reader did when it called them all absent.
        cstate = Counter(_canary_state(r) for r in exe)
        present, absent, unknown = cstate["present"], cstate["absent"], cstate["unknown"]
        measured = present + absent
        if unknown:
            ctx.emit("coverage", {
                "stage": "hardening",
                "mitigation": "canary",
                "measured": measured,
                "unknown": unknown,
                "note": "symbol table unreadable on these binaries; canary "
                        "posture is unmeasured, not absent",
            })
        pct = (present / measured) * 100 if measured else None
        breakdown = (f"{present} present, {absent} absent, {unknown} unknown "
                     f"(symbol table unreadable) of {n} executables")
        # When nothing could be measured this is an instrument/coverage gap,
        # not a vendor defect, and must not be dressed up as one.
        if measured == 0:
            yield Finding(
                detector_id=self.meta.id,
                title=f"Image-wide: stack-canary posture unmeasurable ({unknown}/{n})",
                severity=Severity.INFO,
                axis=Axis.PRESENCE,
                target=str(rootfs.root.name),
                summary=(
                    f"Stack canaries: {breakdown}. No executable exposed a "
                    f"readable symbol table (statically linked and stripped), "
                    f"so canary coverage could not be determined for this "
                    f"image. This is a measurement gap, not a finding of "
                    f"absence."
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                context={"locus": {"scope": "image", "mitigation": "canary"},
                         "executables": n, "present": present, "absent": absent,
                         "unknown": unknown, "measured": measured,
                         "coverage_pct": None, "arch": rootfs.arch},
                triage_notes=["posture unknown; see the elfscan coverage event"],
            )
        elif pct < 80:
            scope_sentence = (
                f"None of the {measured} measured executables were built with "
                f"-fstack-protector"
                if present == 0 else
                f"{absent} of the {measured} measured executables were built "
                f"without -fstack-protector ({present} were)")
            yield Finding(
                detector_id=self.meta.id,
                title=(f"Image-wide: stack canaries absent from "
                       f"{absent} of {measured} measured executables "
                       f"({pct:.0f}% covered)"
                       + (f"; {unknown} unmeasured" if unknown else "")),
                severity=Severity.MEDIUM if present == 0 else Severity.LOW,
                axis=Axis.PRESENCE,
                target=str(rootfs.root.name),
                summary=(
                    f"Stack canaries: {breakdown}. {scope_sentence}. Coverage "
                    f"of {pct:.0f}% is over the {measured} binaries whose "
                    f"symbols were readable"
                    + (f"; {unknown} more could not be measured and are "
                       f"excluded from that denominator." if unknown
                       else ". Reported once rather than per binary.")
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                context={"locus": {"scope": "image", "mitigation": "canary"},
                         "executables": n, "present": present, "absent": absent,
                         "unknown": unknown, "measured": measured,
                         "coverage_pct": round(pct, 1), "arch": rootfs.arch},
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
            # NX/PIE are two-valued. Canary is three-valued: only "absent" is
            # a missing mitigation -- "unknown" means we could not read the
            # symbol table and must not be reported as a defect.
            canary_state = _canary_state(r)
            missing = [k for k, absent in
                       (("NX", not m.get("nx")), ("PIE", not m.get("pie")),
                        ("canary", canary_state == "absent"))
                       if absent]
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

            # Proof. A symbol-based claim ("lacks canary") is only CONFIRMED by
            # evidence that re-derives *that* claim -- the searched string table
            # region -- not by hashing the ELF header, which asserts nothing
            # about symbols. When the finding rests on a phdr-derived mitigation
            # instead (NX/PIE), we have no captured proof for it here, so the
            # finding stays PROBABLE rather than borrowing a proof it cannot
            # support. Asserting a proof the artifact does not back is the same
            # class of error as the detector's old false "absent".
            if "canary" in missing:
                proof = _build_canary_proof(r, rootfs, ctx)
                if proof is not None:
                    try:
                        f.confirm(proof, ctx.artifact_root)
                    except Exception:
                        f.confidence = Confidence.PROBABLE
                        f.triage_notes.append(
                            "canary proof did not verify; left unconfirmed")
                else:
                    f.confidence = Confidence.PROBABLE
                    f.triage_notes.append(
                        "no raw symbol-table region available to prove the "
                        "canary claim (symtab-section source); left unconfirmed")
            else:
                # NX/PIE-only finding: absence is read from the program headers,
                # which we do not currently persist as a proof artifact.
                f.confidence = Confidence.PROBABLE
                f.triage_notes.append(
                    "NX/PIE absence is read from the program headers; no proof "
                    "artifact is captured for phdr-derived mitigations yet")
            yield f


__all__ = ["HardeningAnalyzer"]
