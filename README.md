# Sentinel — firmware security analysis

Point it at a firmware image. It extracts, analyses, optionally boots the
thing, and reports findings that carry evidence you can re-check later.

The design rule everything else follows from:

> A finding is only `confirmed` if it carries a proof artifact that a
> deterministic verifier can re-check offline — no network, no model, just
> stored bytes.

`Finding.confirm()` runs the verifier at the moment of detection and raises
if it fails. There is no other path to `confirmed`: not a config flag, not a
high heuristic score, not an LLM agreeing with itself. A detector that cannot
write a verifier is structurally incapable of producing a confirmed finding.

That is a stronger and more useful claim than "low false positive rate",
because it survives contact with a maintainer. When a vendor asks why you
believe something, the answer is a stored file, an offset, and a hash that
still matches.

## Presence is not reachability

The second idea, and the one that removes most firmware-scanner noise.

| axis | claim | decidable? |
|---|---|---|
| `presence` | these bytes are at this offset in this file | yes, provably |
| `reachability` | an unauthenticated caller can influence this | not from a filesystem dump |

Static analysis may only claim presence. A hardcoded hash in `/etc/shadow` is
a confirmed presence finding forever; it becomes a reachability finding only
when a running service accepts it and both transcripts are stored.

Most scanners conflate the two, which is why their output needs re-triage by
hand. Here the distinction is in the data model, so a report can say exactly
how much is proven.

## Confidence tiers

| tier | meaning |
|---|---|
| `confirmed` | proof artifact exists and re-verified. Reported by default. |
| `probable` | several independent signals agree, no single re-checkable oracle. Separate queue. |
| `candidate` | one weak signal. Version-string CVE matches live here almost always. |
| `refuted` | revalidation disproved it. Kept, never deleted — refutations tune the heuristics. |

## The pipeline

```
acquire ─→ unpack ─→ rootfs ─┬─→ services ──┐
                             ├─→ secrets  ──┤
                             ├─→ elfscan  ──┼─→ triage ─→ report
                             └─→ emulate ─→ reachability ─┘
                                         └─→ webscan ────┘
```

Checkpoints are resumable and fingerprinted on (stage version, config,
upstream fingerprints). Change the image or bump a stage and it re-runs;
otherwise it loads from cache. A failed stage blocks only its dependents —
independent branches still produce findings.

`emulate`, `reachability` and `webscan` are optional by design. A run that
yields 30 confirmed presence findings and never boots QEMU is a good run.

## Install

```bash
git clone <your remote> && cd sentinel-firmware
go build -o bin/elfscan ./go/elfscan
./extend_fixture.sh
python3 test_regressions.py     # 20 checks, stdlib only
python3 smoke_test.py           # proof gate, checkpoint engine
```

Optional, per lane:

```bash
sudo apt install qemu-system-arm     # full-system emulation (BMCs, ASPEED)
sudo apt install qemu-user-static     # user-mode emulation (CGI binaries)
pip install unblob binwalk            # extraction; not needed for a rootfs
```

`unblob` shells out to a long tail of extractors, several of which will write
outside their output directory on a malformed archive — and vendor images are
malformed routinely. Run extraction in the container (`docker compose build`)
rather than on your host.

## Usage

### A rootfs you already extracted

```bash
python3 scan_rootfs.py /path/to/rootfs --scope BOUNTY-REF-123
```

Skips `acquire`/`unpack`. Warns if the directory looks like an extraction
fragment rather than a root filesystem — a clean report from two top-level
directories is the most dangerous output this tool can produce.

### A full image

```bash
python3 -m sentinel.cli firmware --image images/device.bin \
    --scope HSRC-2026-014 --authorize-sha auto --serve
```

`--serve` runs the live dashboard on `127.0.0.1:8089`; `--wait` holds until
you have it open. `--authorize-sha auto` pins the scope to this file's hash
and prints it; pass an explicit hash instead when you want the run to fail
loudly if someone hands you a different file.

There is no flag that runs without an authorization reference. It goes in the
report, and it is what you point at when a vendor asks why you had their
firmware.

### Reading the evidence

```bash
python3 inspect_run.py runs/<id>                     # re-verify every proof
python3 inspect_run.py runs/<id> --target etc/shadow --reveal
```

Reports store `value_sha256`, never the credential — a `report.json` you
attach to a disclosure email should not be a credential dump. Values live in
the blob store and this is what reads them. Masked unless `--reveal`;
multi-line key material is withheld entirely.

The re-verification matters more than the display. Every confirmed proof is
re-run against stored bytes at inspect time. A proof that no longer verifies
is a detector bug or a corrupted artifact store, and either way you want to
know before you cite it.

### Booting the image

For boards QEMU models — ASPEED AST2400/2500/2600, which covers most
OpenBMC targets:

```bash
qemu-system-arm -M help | grep -i bmc
```

See `sentinel/firmware/emulate_system.py`. The guest gets SLIRP with
`restrict=on`, so nothing but the forwarded port goes anywhere. A BMC that
reaches a vendor endpoint during boot is making a connection from your
address that you did not intend.

Once a service answers, it is an ordinary HTTP target and detectors can make
reachability claims with stored transcripts.

## Layout

```
sentinel/core/contracts.py      findings, proofs, confidence, scope
sentinel/core/verifiers.py      the offline re-checks; one per proof kind
sentinel/core/checkpoint.py     resumable DAG + SSE events
sentinel/core/goworker.py       JSON-over-stdio bridge to Go workers
sentinel/firmware/unpack.py     extraction + rootfs scoring
sentinel/firmware/analyzers/    secrets, services, hardening, http_auth
sentinel/firmware/emulate.py         user-mode (CGI binaries)
sentinel/firmware/emulate_system.py  full-system (ASPEED boards)
sentinel/templates/SCHEMA.md    declarative detector format
go/elfscan/main.go              concurrent ELF mitigation scanner
ui/firmware_run.html            live checkpoint view
CHECKLIST.md                    what a complete assessment covers
```

## Adding a detector

Pick the path by how the finding gets proved, not by how hard the
vulnerability class sounds. Declarative YAML when the proof is a byte match,
a validated pattern, or a control/probe differential — see
`sentinel/templates/SCHEMA.md`. A Python or Go plugin when it needs real
logic.

Either way, declaring `can_confirm: true` requires a proof kind with a
registered verifier. The registry enforces it.

Add the regression case in the same commit. Every case in
`test_regressions.py` corresponds to a bug that shipped and was caught by
running against real firmware, not by imagining what might break — the
fixture has never found anything, it only stops things from breaking twice.

## What it does not do

- **Exploitation.** Detection and evidence capture only. No payloads, no
  weaponisation.
- **Follow compiled startup.** Where `/init` is busybox and rcS hands off to
  a proprietary supervisor, service discovery cannot say what runs. It
  reports that as a coverage gap rather than reporting zero services, because
  a silent zero implies a device has no network surface.
- **Decide exploitability statically.** Reachability needs a runtime oracle.
- **The template catalogue.** Schema and verifiers work; the OWASP template
  set is not written yet.
```
