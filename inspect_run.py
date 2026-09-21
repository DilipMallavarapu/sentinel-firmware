#!/usr/bin/env python3
"""
Read the evidence behind a run's findings.

    python3 inspect_run.py runs/224754c14ab1
    python3 inspect_run.py runs/224754c14ab1 --target etc_ro/passwd
    python3 inspect_run.py runs/224754c14ab1 --reveal

Reports redact credential values by design -- a report.json you can attach to
a disclosure email should not be a credential dump. The values are in the
blob store, and this is the tool that reads them.

Two jobs:

  1. Re-verify. Every confirmed finding's proof is re-run against the stored
     bytes, right now, offline. This is the claim the whole architecture
     rests on, and it is worth exercising on real runs rather than trusting
     that it held at detection time. A finding that no longer verifies is a
     bug in the detector or a corrupted artifact store, and either way you
     want to know before you cite it.

  2. Show context. The matched bytes with surrounding lines, so you can make
     the call a scanner cannot: is this a device credential, a build
     artifact, or a default the vendor documents publicly?

Values are masked unless you pass --reveal, so you can page through findings
on a shared screen without leaking them into a screenshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.core import verifiers  # noqa: F401,E402  (registers verifiers)
from sentinel.core.contracts import ProofArtifact, verify_proof  # noqa: E402

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def mask(value: str, reveal: bool) -> str:
    if reveal or len(value) <= 8:
        return value
    return f"{value[:3]}{'*' * (len(value) - 6)}{value[-3:]}"


def context_lines(data: bytes, offset: int, length: int,
                  before: int = 1, after: int = 1) -> list[tuple[bool, str]]:
    """Return (is_match_line, text) around the offset, line-oriented."""
    start = data.rfind(b"\n", 0, offset) + 1
    end = data.find(b"\n", offset + length)
    end = len(data) if end < 0 else end

    pre_start = start
    for _ in range(before):
        pre_start = data.rfind(b"\n", 0, max(pre_start - 1, 0)) + 1
    post_end = end
    for _ in range(after):
        nxt = data.find(b"\n", post_end + 1)
        post_end = len(data) if nxt < 0 else nxt

    out = []
    for chunk_start, chunk_end, hit in (
        (pre_start, start, False), (start, end, True), (end, post_end, False),
    ):
        text = data[chunk_start:chunk_end].decode("utf-8", "replace")
        for line in text.splitlines():
            if line.strip():
                out.append((hit, line.rstrip()[:200]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dir")
    ap.add_argument("--target", help="only findings whose target contains this")
    ap.add_argument("--tier", default="confirmed",
                    choices=["confirmed", "probable", "candidate", "all"])
    ap.add_argument("--reveal", action="store_true",
                    help="print credential values unmasked")
    ap.add_argument("--context", type=int, default=1, help="lines either side")
    args = ap.parse_args()

    root = Path(args.run_dir)
    report = root / "report.json"
    if not report.is_file():
        print(f"no report.json in {root}", file=sys.stderr)
        return 1

    findings = json.loads(report.read_text())["findings"]
    if args.tier != "all":
        findings = [f for f in findings if f["confidence"] == args.tier]
    if args.target:
        findings = [f for f in findings if args.target in f["target"]]
    findings.sort(key=lambda f: SEV_ORDER.get(f["severity"], 9))

    if not findings:
        print("nothing matches")
        return 0

    verified = failed = no_proof = 0

    for f in findings:
        print(f"\n{'─' * 76}")
        print(f"{f['severity'].upper():<9} {f['title']}")
        print(f"{'':<9} {f['axis']} · {f.get('cwe') or '-'} · {f['detector_id']}")

        proof = f.get("proof")
        if not proof:
            no_proof += 1
            print(f"{'':<9} no proof artifact (tier: {f['confidence']})")
            continue

        pa = ProofArtifact(kind=proof["kind"], claim=proof["claim"],
                           blobs=proof.get("blobs", []))
        try:
            ok = verify_proof(pa, root)
        except Exception as exc:
            ok = False
            print(f"{'':<9} verifier error: {exc}")
        verified += ok
        failed += not ok
        print(f"{'':<9} proof {pa.kind} {pa.fingerprint()}: "
              f"{'re-verified' if ok else 'DOES NOT VERIFY'}")

        ctx = f.get("context", {})
        n = ctx.get("occurrences", 1)
        offsets = ctx.get("all_offsets") or [proof["claim"].get("offset")]
        if n > 1:
            print(f"{'':<9} {n} occurrences; showing all")

        blob = root / proof["claim"].get("blob", "")
        if not blob.is_file():
            print(f"{'':<9} blob missing: {proof['claim'].get('blob')}")
            continue
        data = blob.read_bytes()

        for off in [o for o in offsets if o is not None][:20]:
            length = proof["claim"].get("length", 16)
            print()
            # A multi-line match (a PEM block, a certificate) cannot be
            # masked span-by-span, and printing a private key in full to a
            # terminal nobody asked to see it on is worse than unhelpful.
            span = data[off:off + length]
            # Hardening proofs pin the ELF header. Printing 64 bytes of
            # machine code as "context lines" is noise that buries the
            # findings either side of it.
            if b"\x00" in span or data[:4] == b"\x7fELF":
                print(f"  @{off:<8} ▶ [binary, {length} bytes] "
                      f"sha256 {hashlib.sha256(span).hexdigest()[:32]}")
                continue
            if b"\n" in span and not args.reveal:
                first = span.split(b"\n", 1)[0].decode("utf-8", "replace")
                print(f"  @{off:<8} ▶ {first[:70]}")
                print(f"           │ [{length} bytes, {span.count(chr(10).encode())} "
                      f"lines withheld -- pass --reveal to print]")
                print(f"           │ sha256 {hashlib.sha256(span).hexdigest()[:32]}")
                continue
            for is_hit, line in context_lines(data, off, length, args.context,
                                              args.context):
                if not is_hit:
                    print(f"           │ {line}")
                    continue
                shown = line
                if not args.reveal:
                    # Mask the matched span only, so the key stays readable.
                    raw = data[off:off + length].decode("utf-8", "replace")
                    if raw in line:
                        shown = line.replace(raw, mask(raw, False))
                print(f"  @{off:<8} ▶ {shown}")

    print(f"\n{'─' * 76}")
    print(f"{verified} proof(s) re-verified, {failed} failed, "
          f"{no_proof} finding(s) without a proof")
    if failed:
        print("a proof that no longer verifies is a detector bug or a "
              "corrupted artifact store; do not cite that finding")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
