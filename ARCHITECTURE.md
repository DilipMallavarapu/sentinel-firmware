# Sentinel — firmware lane

Extends the existing web platform to firmware, on the same contracts, with a
false-positive model that is enforced rather than promised.

## The rule everything hangs off

A finding reaches `CONFIRMED` only by calling `Finding.confirm(proof, root)`,
and that call runs the proof's verifier immediately. Verifiers are offline,
deterministic, network-free and model-free. There is no other code path to
`CONFIRMED` — not a config flag, not a high heuristic score, not an LLM
agreeing with itself twice.

The practical consequence: `confirmed` findings can be re-verified at report
time, at submission time, and by the vendor three months later from the same
stored bytes. That is a stronger claim than "low false positive rate" and it
is the one worth making in a disclosure.

## Presence vs reachability

Most firmware-scanner noise comes from one conflation:

- **presence** — "these bytes are at this offset in this file". Decidable.
  Provable. This is where static firmware analysis lives.
- **reachability** — "an unauthenticated caller can reach this". Not
  decidable from a filesystem dump.

Static stages may only claim presence. Reachability requires a `runtime_diff`
proof from the emulation lane. A hardcoded hash in `/etc/shadow` is a
confirmed presence finding forever; it becomes a reachability finding only
when the emulated device accepts it.

## The DAG

    acquire → unpack → rootfs ─┬→ services ─┐
                               ├→ secrets  ─┤
                               ├→ elfscan  ─┼→ triage → report
                               └→ emulate → webscan ─┘

Checkpoints are resumable and fingerprinted on (stage version, config,
upstream fingerprints). Change the image or bump a stage version and it
re-runs; otherwise it is served from cache. A failed stage blocks only its
dependents — independent branches still produce findings.

`emulate` and `elfscan` are optional by design. A run that yields 30
confirmed presence findings and never boots QEMU is a good run.

## Where the two lanes meet

`webscan` takes the emulated device's base URL and hands it to the *existing*
web detector suite unchanged. Every XSS, SQLi, auth and header detector
already written becomes a firmware detector at that moment, and its findings
carry `runtime_diff` proofs. This is the payoff for putting both lanes on
`core.contracts`.

## Agents

Agents propose; the pipeline executes. Three roles, each narrowly scoped:

- **planner** — returns checkpoint ids to enable or skip plus a parameter
  dict, validated against a whitelist. It cannot name a subprocess.
- **triage** — may add a note, demote, or refute. It cannot promote. The
  promotion path requires a verifier and no model output is a verifier.
- **reporter** — drafts prose from confirmed findings only.

Keeping the agents on the demote-only side of the line is what stops the
false-positive rate from becoming a function of model temperature.

## Layout

    sentinel/core/contracts.py    findings, proofs, confidence, scope
    sentinel/core/verifiers.py    the offline re-checks; add one per proof kind
    sentinel/core/checkpoint.py   resumable DAG engine + SSE events
    sentinel/core/goworker.py     JSON-over-stdio bridge to Go workers
    sentinel/firmware/models.py   image, rootfs, services, emulated target
    sentinel/firmware/unpack.py   unblob/binwalk/carve + rootfs scoring
    sentinel/firmware/analyzers/  secrets, hardening, services
    sentinel/firmware/pipeline.py the DAG and its stages
    sentinel/templates/SCHEMA.md  declarative detector format
    go/elfscan/main.go            concurrent ELF mitigation scanner
    ui/firmware_run.html          live checkpoint + findings view
    smoke_test.py                 proves the confirm/verify gate holds

## Running it

    go build -o bin/elfscan ./go/elfscan
    python3 smoke_test.py

    from sentinel.core.contracts import Scope
    from sentinel.firmware.pipeline import analyze_firmware

    scope = Scope(authorization_ref="HSRC-2026-014",
                  firmware_sha256=["<sha of the image you are authorized to test>"])
    analyze_firmware("DS-K1T671M.bin", scope, emit=my_sse_emitter)

Scope is checked at `acquire`. An image whose hash is not listed is refused
before anything is extracted.

## Next, in order

1. Port the existing web detectors to emit `differential` proofs. They already
   do the work; they need to store both controls and the probe body.
2. Wire one emulation backend. Start with user-mode `qemu-*-static` + chroot
   against a single CGI binary — far more tractable than a full system boot,
   and it is enough to produce `runtime_diff` proofs.
3. Build the template loader against `templates/SCHEMA.md`, then write the
   catalogue in oracle order (byte_match batch first).
4. Add `known_benign_keys.txt` and a refutation corpus from images you have
   already triaged. Refutation lists are the cheapest false-positive
   reduction available and they compound.
