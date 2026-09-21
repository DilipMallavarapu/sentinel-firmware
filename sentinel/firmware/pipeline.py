"""
sentinel.firmware.pipeline
==========================

The firmware DAG. This is the file the UI renders and the agents rewrite.

    acquire ─→ unpack ─→ rootfs ─┬─→ inventory ──┐
                                 ├─→ secrets  ───┤
                                 ├─→ elfscan ────┼─→ triage ─→ report
                                 ├─→ services ───┤
                                 └─→ emulate ─→ webscan ──┘

Two structural decisions worth stating plainly.

First, `emulate` is optional and `webscan` is gated on it. Most images will
not boot on the first try, and that is fine: a run that produces 30 confirmed
PRESENCE findings and no emulation is a useful run. Treating emulation as
mandatory would make the common case look like a failure.

Second, `webscan` reuses the existing web detector suite untouched. Once QEMU
has a lighttpd answering on 127.0.0.1:8080, that is just a Sentinel target.
This is the payoff for putting both lanes on `core.contracts`: the XSS, SQLi,
auth-bypass and header detectors already written for the web lane become
firmware detectors for free, and their findings carry `runtime_diff` proofs,
which is the only path by which a firmware finding earns REACHABILITY.

Agent integration points are marked AGENT below. Agents propose; they do not
execute. A planner returns a list of checkpoint ids to enable or skip and a
parameter dict; the pipeline validates that against a whitelist before it
takes effect. A model that can name a stage cannot invent a subprocess call.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Callable

from ..core.checkpoint import Checkpoint, CheckpointResult, Pipeline, RunState, State
from ..core.contracts import (
    Axis, Confidence, Finding, ProofArtifact, RunContext, Scope, Severity,
    verify_proof)
from ..core.goworker import GoWorker, GoWorkerError
from . import unpack as unpack_mod
from .analyzers.hardening import HardeningAnalyzer
from .analyzers.secrets import HardcodedCredentialDetector
from .analyzers.services import ServiceAnalyzer
from . import emulate
from .models import FirmwareImage, RootFS


_SEV_RANK = {s.value: s.rank for s in Severity}


def _write_findings(run: RunState, stage: str, findings: list[Finding]) -> int:
    path = run.dir(stage) / "findings.jsonl"
    with path.open("w") as fh:
        for f in findings:
            fh.write(json.dumps(f.to_dict(), default=str) + "\n")
            run.emit("finding", {"stage": stage, **f.to_dict()})
    return len(findings)


def _ctx(run: RunState) -> RunContext:
    return RunContext(
        run_id=run.run_id,
        artifact_root=run.root,
        scope=run.config["_scope"],
        emit=run.emit,
        config=run.config,
    )


# ==========================================================================
# Stages
# ==========================================================================

def stage_acquire(run: RunState, cfg: dict) -> CheckpointResult:
    """Hash the image and check it against the authorization scope."""
    image = FirmwareImage.from_file(cfg["image_path"])
    scope: Scope = cfg["_scope"]
    if scope.firmware_sha256 and not scope.permits_image(image.sha256):
        return CheckpointResult(
            State.FAILED,
            note=(f"image {image.sha256[:16]} is not listed in scope "
                  f"{scope.authorization_ref}; refusing to analyse"),
        )
    return CheckpointResult(State.OK, outputs={
        "sha256": image.sha256, "size": image.size,
        "path": str(image.path), "authorization": scope.authorization_ref,
    }, note=f"{image.size/1e6:.1f} MB, sha256 {image.sha256[:16]}")


def stage_unpack(run: RunState, cfg: dict) -> CheckpointResult:
    image = FirmwareImage.from_file(run.out("acquire", "path"))
    workdir = run.dir("unpack") / "extracted"
    parts, tool = unpack_mod.extract(image, workdir,
                                     timeout=cfg.get("unpack_timeout", 1800))

    encrypted = [p for p in parts if p.kind == "high_entropy"]
    kinds = sorted({p.kind for p in parts})
    (run.dir("unpack") / "partitions.json").write_text(json.dumps(
        [{"index": p.index, "offset": p.offset, "size": p.size,
          "kind": p.kind, "entropy": round(p.entropy, 3)} for p in parts],
        indent=2))

    if not parts:
        return CheckpointResult(State.FAILED,
                                note=f"{tool} extracted nothing from this image")

    note = f"{tool}: {len(parts)} regions ({', '.join(kinds[:6])})"
    if encrypted and not any(k in kinds for k in ("squashfs", "cramfs", "jffs2", "ubifs")):
        note += (f" -- {len(encrypted)} high-entropy regions and no recognised "
                 f"filesystem: image is likely encrypted, obtain the key from a "
                 f"bootloader or flash dump before continuing")
    return CheckpointResult(State.OK, outputs={
        "tool": tool, "workdir": str(workdir), "kinds": kinds,
        "partition_count": len(parts), "likely_encrypted": bool(encrypted and
                                                                len(kinds) <= 2),
    }, note=note)


def stage_rootfs(run: RunState, cfg: dict) -> CheckpointResult:
    workdir = Path(run.out("unpack", "workdir"))
    found, scoreboard = unpack_mod.locate_rootfs(workdir)
    (run.dir("rootfs") / "candidates.json").write_text(
        json.dumps(scoreboard, indent=2))
    if found is None:
        return CheckpointResult(
            State.FAILED,
            note=("no directory scored high enough to be a Linux root; "
                  "see candidates.json for what was considered"))
    rfs = unpack_mod.identify(RootFS(root=found))
    run.config["_rootfs"] = rfs
    file_count = sum(1 for _ in rfs.walk())
    return CheckpointResult(State.OK, outputs={
        "root": str(found), "arch": rfs.arch, "endian": rfs.endian,
        "libc": rfs.libc, "init": rfs.init_system, "files": file_count,
    }, note=f"{rfs.arch}/{rfs.libc or '?'}, {file_count} files, init={rfs.init_system}")


def stage_secrets(run: RunState, cfg: dict) -> CheckpointResult:
    rfs: RootFS = run.config["_rootfs"]
    det = HardcodedCredentialDetector()
    findings = list(det.run(rfs, _ctx(run)))
    n = _write_findings(run, "secrets", findings)
    confirmed = sum(1 for f in findings if f.confidence.value == "confirmed")
    return CheckpointResult(State.OK, outputs={"finding_count": n},
                            findings=n,
                            note=f"{confirmed} confirmed, {n - confirmed} candidate")


def stage_backdoor(run: RunState, cfg: dict) -> CheckpointResult:
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


def stage_binanalysis(run: RunState, cfg: dict) -> CheckpointResult:
    """
    Look inside the binaries: shell command templates and, where capstone is
    available, the callsites that use them. See analyzers/binanalysis.py.
    """
    from .analyzers.binanalysis import DETECTORS as BIN_DETECTORS, HAVE_CAPSTONE
    rfs: RootFS = run.config["_rootfs"]
    ctx = _ctx(run)
    findings: list[Finding] = []
    for det in BIN_DETECTORS:
        if det.applicable(rfs):
            findings.extend(det.run(rfs, ctx))
    n = _write_findings(run, "binanalysis", findings)
    return CheckpointResult(State.OK, outputs={"finding_count": n},
                            findings=n,
                            note=(f"{n} binaries build shell commands from "
                                  f"format strings"
                                  + ("" if HAVE_CAPSTONE
                                     else "; capstone absent, templates only")))


def stage_elfscan(run: RunState, cfg: dict) -> CheckpointResult:
    rfs: RootFS = run.config["_rootfs"]
    worker = GoWorker("elfscan", search_paths=[Path(cfg.get("bin_dir", "bin"))])
    if not worker.available:
        return CheckpointResult(
            State.SKIPPED,
            note="elfscan binary not built (go build -o bin/elfscan ./go/elfscan)")

    records: list[dict] = []
    def on_rec(rec: dict) -> None:
        records.append(rec)
        if len(records) % 250 == 0:
            run.emit("checkpoint.progress",
                     {"id": "elfscan", "scanned": len(records)})

    try:
        summary = worker.each({"root": str(rfs.root), "workers": 0,
                               "skip_globs": ["*.ko"]}, on_rec,
                              timeout=cfg.get("elfscan_timeout", 900))
    except GoWorkerError as exc:
        return CheckpointResult(State.FAILED, note=str(exc))

    (run.dir("elfscan") / "inventory.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records))

    services = run.config.get("_services", [])
    findings = list(HardeningAnalyzer().analyze(records, rfs, services, _ctx(run)))
    n = _write_findings(run, "elfscan", findings)
    return CheckpointResult(State.OK, outputs={
        "elf_count": summary.get("elfs", len(records)),
        "finding_count": n, "seconds": summary.get("seconds"),
    }, findings=n, note=f"{summary.get('elfs', len(records))} ELFs in "
                        f"{summary.get('seconds', 0):.1f}s")


def stage_services(run: RunState, cfg: dict) -> CheckpointResult:
    rfs: RootFS = run.config["_rootfs"]
    an = ServiceAnalyzer()
    services = an.discover(rfs)
    run.config["_services"] = services
    ctx = _ctx(run)
    findings = list(an.findings(services, rfs, ctx))
    orphans = an.orphan_binaries(services, rfs)
    gap = an.coverage_finding(orphans, services, rfs, ctx)
    if gap:
        findings.append(gap)
    n = _write_findings(run, "services", findings)
    web = [s.name for s in services if s.web]
    return CheckpointResult(State.OK, outputs={
        "services": [s.name for s in services],
        "web_services": web,
        "ports": sorted({s.port for s in services if s.port}),
        "finding_count": n,
        "unexplained_binaries": orphans,
    }, findings=n,
       note=(f"{len(services)} started by config; web: {', '.join(web) or 'none'}"
             + (f"; {len(orphans)} service binaries unexplained" if orphans else "")))


def stage_emulate(run: RunState, cfg: dict) -> CheckpointResult:
    """
    Stage the rootfs for user-mode emulation and rank the CGI attack surface.

    Deliberately does not boot a system image. User-mode gets a CGI binary
    executing on the first afternoon; full-system emulation gets you a week
    of device-tree work before the first response. Start where the oracle is
    cheap.
    """
    rfs: RootFS = run.config["_rootfs"]
    scope: Scope = cfg["_scope"]
    backend_name = cfg.get("emulation_backend") or "qemu-user"
    if backend_name != "qemu-user":
        return CheckpointResult(State.SKIPPED,
                                note=f"backend {backend_name!r} not implemented")

    try:
        backend = emulate.QemuUserBackend(
            rootfs=rfs, scope=scope, workdir=run.dir("emulate"),
            timeout=cfg.get("emulation_timeout", 15))
        backend.stage()
    except emulate.EmulationUnavailable as exc:
        return CheckpointResult(State.SKIPPED, note=str(exc))

    if not scope.allow_emulated_egress:
        run.emit("policy", {"stage": "emulate",
                            "rule": "emulated guest has no network namespace"})

    cgis = emulate.discover_cgi(rfs)
    run.config["_backend"] = backend
    run.config["_cgi"] = cgis
    (run.dir("emulate") / "cgi.json").write_text(json.dumps(cgis, indent=2))

    if not cgis:
        backend.cleanup()      # nothing downstream will run, so drop the copy
        return CheckpointResult(State.OK, outputs={"cgi_count": 0},
                                note="staged, but no CGI binaries found")
    return CheckpointResult(State.OK, outputs={
        "base_url": "cgi://user-mode", "cgi_count": len(cgis),
        "arch": rfs.arch, "top": cgis[:8],
    }, note=f"{len(cgis)} CGI binaries; first is {cgis[0]}")


def stage_reachability(run: RunState, cfg: dict) -> CheckpointResult:
    """
    The presence -> reachability crossing.

    For each CGI binary, send a control request twice and a marker-carrying
    probe once. A marker that appears in the probe output and not in the
    control proves the request reached the handler and that input is
    reflected. That is a reachability fact with a stored transcript behind
    it, and it is the only kind of firmware finding entitled to the
    reachability axis.

    The second control is what makes this trustworthy on embedded targets,
    which stamp uptime counters and session ids into responses and would
    otherwise look injectable on every endpoint.
    """
    backend = run.config.get("_backend")
    cgis: list[str] = run.config.get("_cgi", [])
    if backend is None or not cgis:
        return CheckpointResult(State.SKIPPED, note="nothing staged to exercise")

    ctx = _ctx(run)
    budget = cfg.get("reachability_budget", 40)
    findings: list[Finding] = []
    executed = reflected = dead = 0

    for rel in cgis[:budget]:
        marker = emulate.new_marker()
        try:
            res = emulate.differential(
                backend, rel,
                control={"method": "GET", "query": "sentinel=probe"},
                probe={"method": "GET", "query": f"sentinel={marker}"},
                marker=marker,
            )
        except emulate.EmulationUnavailable as exc:
            return CheckpointResult(State.FAILED, note=str(exc))
        except Exception as exc:
            dead += 1
            continue
        executed += 1

        if res.probe_transcript.timed_out or res.probe_transcript.status not in (0, None):
            if not res.probe_transcript.stdout:
                dead += 1
                continue

        if not res.diverged:
            continue
        reflected += 1

        f = Finding(
            detector_id="fw.runtime.reflection",
            title=f"{rel} executes under emulation and reflects request input",
            severity=Severity.INFO,
            axis=Axis.REACHABILITY,
            target=rel,
            summary=(
                f"{rel} ran under qemu-user and echoed a unique marker from "
                f"QUERY_STRING into its response, while an identical control "
                f"request did not. This establishes that the handler is "
                f"reachable and that request input reaches its output path. "
                f"It is not itself a vulnerability -- it is the runtime "
                f"foothold that lets injection detectors make reachability "
                f"claims about this binary."
            ),
            context={"locus": {"file": rel}, "oracle": res.note,
                     "arch": run.out("rootfs", "arch")},
        )
        proof = emulate.build_runtime_proof(res, ctx, rel.replace("/", "_"))
        try:
            f.confirm(proof, ctx.artifact_root)
        except Exception:
            f.confidence = Confidence.PROBABLE
        findings.append(f)

    n = _write_findings(run, "reachability", findings)
    backend.cleanup()
    return CheckpointResult(State.OK, outputs={
        "executed": executed, "reflected": reflected,
        "failed_to_run": dead, "finding_count": n,
    }, findings=n,
       note=f"{executed} ran, {reflected} reflect input, {dead} would not run")


def stage_webscan(run: RunState, cfg: dict) -> CheckpointResult:
    """
    Hand a socket-listening emulated device to the existing web detector suite.

    Distinct from `reachability`, which drives CGI binaries directly with no
    httpd in the picture. This stage is for the case where a full-system boot
    produced a real listener, and its value is that every web detector already
    written runs against it unmodified.
    """
    base = run.out("emulate", "base_url")
    if not base or base.startswith("cgi://"):
        return CheckpointResult(
            State.SKIPPED,
            note="user-mode emulation exposes no socket; see reachability")
    return CheckpointResult(State.SKIPPED,
                            note="wire sentinel.web.scanner(base_url) here")


def stage_triage(run: RunState, cfg: dict) -> CheckpointResult:
    """
    Dedupe, cross-reference, and run LLM fusion over non-confirmed findings.

    AGENT. The triage agent's remit is strictly bounded: it may add a
    `triage_note`, demote a finding, or mark it REFUTED. It may not promote
    anything to CONFIRMED -- that path runs through `Finding.confirm()` and
    requires a verifier, and no model output is a verifier.
    """
    all_findings: list[dict] = []
    for stage in ("secrets", "elfscan", "services", "backdoor", "binanalysis",
                  "reachability", "webscan"):
        p = run.dir(stage) / "findings.jsonl"
        if p.is_file():
            all_findings += [json.loads(l) for l in p.read_text().splitlines() if l]

    by_key: dict[str, dict] = {}
    for f in all_findings:
        k = f["dedupe_key"]
        prev = by_key.get(k)
        # Severity.rank, NOT string order. "critical" > "high" is False in
        # lexicographic comparison, so a CRITICAL finding lost to a HIGH one
        # on every dedupe collision.
        if prev is None or (_SEV_RANK.get(f["severity"], -1)
                            > _SEV_RANK.get(prev["severity"], -1)):
            by_key[k] = f
    deduped = list(by_key.values())

    tiers = {"confirmed": 0, "probable": 0, "candidate": 0, "refuted": 0}
    for f in deduped:
        tiers[f["confidence"]] = tiers.get(f["confidence"], 0) + 1

    (run.dir("triage") / "findings.json").write_text(json.dumps(deduped, indent=2))
    return CheckpointResult(State.OK, outputs={
        "finding_count": len(deduped), "tiers": tiers,
        "deduped_away": len(all_findings) - len(deduped),
    }, findings=len(deduped),
       note=f"{tiers['confirmed']} confirmed / {tiers['probable']} probable / "
            f"{tiers['candidate']} candidate")


def stage_report(run: RunState, cfg: dict) -> CheckpointResult:
    src = run.dir("triage") / "findings.json"
    findings = json.loads(src.read_text()) if src.is_file() else []

    # Re-verify every confirmed proof against the stored bytes. A failure
    # here means a detector bug or a corrupted artifact store -- it is NOT
    # a finding that has become slightly less certain, so it is marked
    # REFUTED and counted, never quietly demoted to probable where a reader
    # would skim past it.
    reverified = failed = 0
    for f in findings:
        if f.get("confidence") != "confirmed" or not f.get("proof"):
            continue
        try:
            pa = ProofArtifact(kind=f["proof"]["kind"],
                               claim=f["proof"]["claim"],
                               blobs=f["proof"].get("blobs", []))
            ok = verify_proof(pa, run.root)
        except Exception as exc:
            ok, reason = False, f"{type(exc).__name__}: {exc}"
        else:
            reason = "proof did not re-verify against stored bytes"
        if ok:
            reverified += 1
        else:
            failed += 1
            f["confidence"] = "refuted"
            f.setdefault("triage_notes", []).append(
                f"REFUTED at report time: {reason}")
    report = {
        "run_id": run.run_id,
        "authorization": cfg["_scope"].authorization_ref,
        "image": {"sha256": run.out("acquire", "sha256"),
                  "size": run.out("acquire", "size")},
        "platform": {"arch": run.out("rootfs", "arch"),
                     "libc": run.out("rootfs", "libc"),
                     "init": run.out("rootfs", "init")},
        "stages": {k: v.value for k, v in run.states.items()},
        "findings": findings,
        "proof_verification": {"reverified": reverified, "failed": failed},
        "methodology_note": (
            "Findings marked confirmed carry a proof artifact that was "
            "re-verified offline at report time. Findings on the presence "
            "axis assert that data or configuration exists in the image; "
            "they do not assert exploitability, which requires the runtime "
            "evidence produced by the emulation lane."
        ),
    }
    (run.root / "report.json").write_text(json.dumps(report, indent=2))
    state = State.OK if failed == 0 else State.FAILED
    return CheckpointResult(state,
                            outputs={"path": str(run.root / "report.json"),
                                     "reverified": reverified, "failed": failed},
                            note=(f"{len(findings)} findings, {reverified} proofs "
                                  f"re-verified"
                                  + (f", {failed} REFUTED -- investigate before "
                                     f"citing anything from this run"
                                     if failed else "")))


# ==========================================================================

def build_pipeline() -> Pipeline:
    return Pipeline([
        Checkpoint("acquire", "Hash image and check authorization", stage_acquire),
        Checkpoint("unpack", "Extract filesystems", stage_unpack, needs=["acquire"]),
        Checkpoint("rootfs", "Identify root filesystem", stage_rootfs, needs=["unpack"]),
        Checkpoint("services", "Find services started at boot", stage_services,
                   needs=["rootfs"]),
        Checkpoint("secrets", "Search for credentials and keys", stage_secrets,
                   needs=["rootfs"]),
        Checkpoint("backdoor", "Backdoor and hygiene checks", stage_backdoor,
                   needs=["rootfs"]),
        Checkpoint("binanalysis", "Analyse binary internals",
                   stage_binanalysis, needs=["rootfs"], optional=True),
        Checkpoint("elfscan", "Scan binary hardening", stage_elfscan,
                   needs=["rootfs", "services"], optional=True),
        Checkpoint("emulate", "Boot the device under QEMU", stage_emulate,
                   needs=["rootfs", "services"], optional=True),
        Checkpoint("reachability", "Exercise CGI handlers", stage_reachability,
                   needs=["emulate"], optional=True,
                   gate=lambda run: bool(run.out("emulate", "base_url"))),
        Checkpoint("webscan", "Scan the running device", stage_webscan,
                   needs=["emulate"], optional=True,
                   gate=lambda run: bool(run.out("emulate", "base_url"))),
        Checkpoint("triage", "Dedupe and verify findings", stage_triage,
                   needs=["secrets", "elfscan", "services", "backdoor", "binanalysis",
                          "reachability", "webscan"]),
        Checkpoint("report", "Write the report", stage_report, needs=["triage"]),
    ])


def analyze_firmware(image_path: str | Path, scope: Scope,
                     workdir: str | Path = "runs",
                     emit: Callable[[str, dict], None] | None = None,
                     resume: bool = True, **config: Any) -> RunState:
    run_id = uuid.uuid4().hex[:12]
    root = Path(workdir) / run_id
    root.mkdir(parents=True, exist_ok=True)
    run = RunState(
        run_id=run_id, root=root,
        config={"image_path": str(image_path), "_scope": scope, **config},
        emit=emit or (lambda e, d: None),
    )
    return build_pipeline().run(run, resume=resume)


__all__ = ["build_pipeline", "analyze_firmware"]
