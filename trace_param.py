#!/usr/bin/env python3
"""
Find the function that uses both a parameter name and a command template.

    python3 trace_param.py <binary> gateway iptables
    python3 trace_param.py <binary> --auto --rootfs /path/to/rootfs

`sharedkeys` tells you two strings sit near each other in .rodata. This tells
you whether the same *function* loads both, and at what address — which is
where a disassembler session actually starts.

The distinction matters. Adjacency in .rodata is a statement about how the
compiler laid out literals; co-reference in .text is a statement about code.
Neither proves the parameter's value reaches the command, because the
function may sanitise it or use the two on unrelated paths. What this
removes is the guesswork about *which* of a hundred functions to read.

With --auto it pulls the web root's parameter names and the binary's command
templates itself and reports every pair that shares a function, ranked.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel.firmware.analyzers.binanalysis import (  # noqa: E402
    extract_templates, parse_elf,
)
from sentinel.firmware.analyzers.xref import (  # noqa: E402
    HAVE_CAPSTONE, correlate_in_code, resolve_string_refs, rodata_vaddr,
)

STRING_RE = re.compile(rb"[\x20-\x7e]{4,300}")


def rodata_offsets(view, needles: list[str]) -> dict[str, int]:
    """
    Locate each needle in .rodata, returning label -> file offset.

    The offset must be of the NUL-delimited string the code actually loads,
    not of the printable run that happens to contain it. An earlier version
    returned the run's start, so searching for "gateway" produced the address
    of whatever literal it was embedded in -- an address no instruction ever
    materialises, which made the resolver report zero references on a binary
    that referenced the string perfectly well.
    """
    ro = view.section(".rodata")
    if ro is None:
        return {}
    blob = view.data[ro.offset:ro.offset + ro.size]
    out: dict[str, int] = {}
    for n in needles:
        raw = n.encode()
        start = 0
        while True:
            k = blob.find(raw, start)
            if k < 0:
                break
            start = k + 1
            # A literal begins at the start of the section or just after a
            # NUL. Anything else is an interior match and is not what the
            # code loads.
            if k == 0 or blob[k - 1] == 0:
                out[n] = ro.offset + k
                break
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("needles", nargs="*",
                    help="substrings to locate: a parameter name and part of "
                         "a command template")
    ap.add_argument("--auto", action="store_true",
                    help="derive both sides automatically")
    ap.add_argument("--rootfs", help="rootfs for --auto, to read the web root")
    ap.add_argument("--max-pairs", type=int, default=15)
    args = ap.parse_args()

    if not HAVE_CAPSTONE:
        print("capstone is required: pip install capstone", file=sys.stderr)
        return 2

    data = Path(args.binary).read_bytes()
    view = parse_elf(data)
    if view is None:
        print(f"{args.binary}: not an ELF this tool can parse", file=sys.stderr)
        return 2

    arch = {0x08: "mips", 0x28: "arm", 0xB7: "aarch64"}.get(view.machine,
                                                           hex(view.machine))
    print(f"{args.binary}  arch={arch} endian={'little' if view.little else 'big'}")

    needles = list(args.needles)
    templates: dict[str, int] = {}

    if args.auto:
        for t in extract_templates(view):
            if t.score >= 12:
                templates[t.text] = t.offset
        if not templates:
            print("  no command templates in this binary")
            return 0
        params: list[str] = []
        if args.rootfs:
            from sentinel.firmware.analyzers.sharedkeys import (
                extract_frontend_keywords)
            from sentinel.firmware.models import RootFS
            kws = extract_frontend_keywords(RootFS(root=Path(args.rootfs)))
            blob = view.data[view.section(".rodata").offset:]
            params = [k for k in kws if k.encode() in blob]
            print(f"  {len(kws)} web parameters, {len(params)} present in this binary")
        needles = params
        offsets = rodata_offsets(view, needles)
        offsets.update({f"TEMPLATE: {t[:60]}": o for t, o in templates.items()})
    else:
        if len(needles) < 2:
            ap.error("give at least two needles, or use --auto")
        offsets = rodata_offsets(view, needles)
        missing = [n for n in needles if n not in offsets]
        if missing:
            print(f"  not found in .rodata: {missing}", file=sys.stderr)

    if len(offsets) < 2:
        print("  fewer than two strings located; nothing to correlate")
        return 1

    targets = {rodata_vaddr(view, o) for o in offsets.values()}
    targets.discard(None)
    res = resolve_string_refs(view, targets)
    print(f"  {res.note}")
    if not res.functions:
        # "Found nothing" and "could not analyse" are different answers, and
        # conflating them is how four rounds got spent treating a resolver
        # limitation as evidence about the firmware. Say which this is.
        print("  UNRESOLVED, not clean: no reference to any target address was")
        print("  recovered. This says nothing about the binary -- register")
        print("  tracking here is deliberately shallow and misses any address")
        print("  built across basic blocks, through a GOT page, or via a")
        print("  relocation. Use Ghidra: import, auto-analyze, then Search >")
        print("  For Strings and Show References to Address.")
        return 1

    pairs = correlate_in_code(data, offsets)
    param_only = {n for n in needles}

    shown = 0
    for labels, start, where in pairs:
        tmpl = [l for l in labels if l.startswith("TEMPLATE:")]
        prms = [l for l in labels if l in param_only]
        # A function referencing two parameters and no template is just a
        # config handler. The pairing is what makes it worth reading.
        if args.auto and not (tmpl and prms):
            continue
        shown += 1
        if shown > args.max_pairs:
            break
        print(f"\n  function @ {hex(start)}")
        for lbl in labels:
            sites = ", ".join(hex(a) for a in where[lbl][:4])
            print(f"      {lbl[:78]}")
            print(f"          loaded at {sites}")

    if shown == 0:
        print("\n  no function references both a parameter and a template.")
        print("  The .rodata adjacency was layout, not shared code -- which is")
        print("  exactly the case this tool exists to rule out.")
    else:
        print(f"\n  {min(shown, args.max_pairs)} function(s) to read. Open the "
              f"binary at the address above.")
        print("  Co-reference is not dataflow: the function may sanitise the "
              "value,\n  or use the two on unrelated paths. Read it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
