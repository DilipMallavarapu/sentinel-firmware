#!/usr/bin/env python3
"""
Diagnose how a specific binary actually reaches its strings.

Written after three wrong guesses about MIPS addressing. Rather than assume
a form and report zero when it does not match, this prints what the binary
really does: where the string lives, what the GOT holds, and which
instructions produce an address anywhere near it.

    python3 diag_xref.py <binary> gateway
"""
import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capstone
from sentinel.firmware.analyzers.binanalysis import parse_elf

binpath, needle = sys.argv[1], sys.argv[2].encode()
data = Path(binpath).read_bytes()
v = parse_elf(data)
ro, got, text = v.section(".rodata"), v.section(".got"), v.section(".text")
order = "little" if v.little else "big"

blob = data[ro.offset:ro.offset + ro.size]
pos = blob.find(needle)
if pos < 0:
    print(f"{needle!r} not in .rodata"); sys.exit(1)
target = ro.addr + pos
print(f"string {needle!r} at vaddr {hex(target)} (.rodata {hex(ro.addr)}"
      f"+{hex(pos)}, size {hex(ro.size)})")

gp = got.addr + 0x7FF0
print(f"got {hex(got.addr)} size {hex(got.size)}  ->  $gp = {hex(gp)}")

# What does the GOT actually hold? If entries point at .rodata, a plain lw
# reaches strings. If they point at section anchors, an addiu supplies the
# rest and the distance between the two instructions is what matters.
entries = {}
raw = data[got.offset:got.offset + got.size]
for i in range(0, len(raw) - 3, 4):
    entries[got.addr + i] = int.from_bytes(raw[i:i + 4], order)
in_ro = [a for a in entries.values() if ro.addr <= a < ro.addr + ro.size]
print(f"got entries: {len(entries)}, of which {len(in_ro)} point into .rodata")
if in_ro:
    print(f"  range {hex(min(in_ro))}..{hex(max(in_ro))}")
exact = [k for k, val in entries.items() if val == target]
print(f"  entries pointing exactly at our string: {[hex(k) for k in exact]}")

md = capstone.Cs(capstone.CS_ARCH_MIPS,
                 capstone.CS_MODE_MIPS32 |
                 (capstone.CS_MODE_LITTLE_ENDIAN if v.little
                  else capstone.CS_MODE_BIG_ENDIAN))
ins = list(md.disasm(data[text.offset:text.offset + text.size], text.addr))
print(f"{len(ins)} instructions")

# Replay gp-loads and look for anything that lands on the string, recording
# how far the addiu sat from its lw so the window can be set from evidence.
import re
IMM = re.compile(r"(-?)(?:0x([0-9a-fA-F]+)|(\d+))\s*$")


def imm(s):
    m = IMM.search(s.strip().rstrip(")"))
    if not m:
        return None
    val = int(m.group(2), 16) if m.group(2) else int(m.group(3))
    return -val if m.group(1) else val


pending, hits, gaps = {}, [], collections.Counter()
for i, x in enumerate(ins):
    if x.mnemonic == "lw" and "($gp)" in x.op_str:
        reg = x.op_str.split(",")[0].strip()
        off = imm(x.op_str.split(",", 1)[-1].split("(")[0])
        if off is None:
            continue
        base = entries.get(gp + off)
        if base is None:
            continue
        pending[reg] = (base, i, x.address)
        if base == target:
            hits.append(("direct lw", x.address, 0))
    elif x.mnemonic == "addiu":
        reg = x.op_str.split(",")[0].strip()
        if reg not in pending:
            continue
        base, idx, addr = pending[reg]
        lo = imm(x.op_str.split(",")[-1])
        if lo is None:
            continue
        if lo > 0x7FFF:
            lo -= 0x10000
        if (base + lo) & 0xFFFFFFFF == target:
            gap = i - idx
            gaps[gap] += 1
            hits.append(("lw+addiu", x.address, gap))
        if i - idx > 64:
            pending.pop(reg, None)

print(f"\nreferences found: {len(hits)}")
for kind, addr, gap in hits[:10]:
    print(f"  {kind:<10} at {hex(addr)}  (lw/addiu gap: {gap} instructions)")
if gaps:
    print(f"  gap distribution: {dict(sorted(gaps.items()))}")
    print(f"  -> LUI_WINDOW must be at least {max(gaps)}")
