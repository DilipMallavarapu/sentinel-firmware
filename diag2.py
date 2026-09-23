#!/usr/bin/env python3
"""
Second diagnostic: find out how this binary really forms a .rodata address.

The GOT holds nothing pointing into .rodata, and $gp is too far from the
string for a 16-bit offset, so both implemented paths are impossible here.
Rather than guess a fourth time, this searches the code for whatever does
produce the address and prints the instructions around it.

    python3 diag2.py <binary> gateway
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import capstone
from sentinel.firmware.analyzers.binanalysis import parse_elf

binpath, needle = sys.argv[1], sys.argv[2].encode()
data = Path(binpath).read_bytes()
v = parse_elf(data)
order = "little" if v.little else "big"
ro = v.section(".rodata")
pos = data[ro.offset:ro.offset + ro.size].find(needle)
target = ro.addr + pos
print(f"target {needle!r} = {hex(target)}")

# 1. Does the literal 32-bit address appear anywhere in the file at all?
word = target.to_bytes(4, order)
where = []
for name, s in v.sections.items():
    if not s.size or not s.offset:
        continue
    blob = data[s.offset:s.offset + s.size]
    k = blob.find(word)
    if k >= 0:
        where.append(f"{name}+{hex(k)}")
print(f"literal address stored in: {where or 'nowhere'}")

# 2. What do GOT entries actually point at?
got = v.section(".got")
if got:
    raw = data[got.offset:got.offset + got.size]
    vals = [int.from_bytes(raw[i:i + 4], order) for i in range(0, len(raw) - 3, 4)]
    buckets = {}
    for val in vals:
        hit = next((n for n, s in v.sections.items()
                    if s.addr and s.addr <= val < s.addr + s.size), None)
        buckets[hit or ("zero" if val == 0 else "elsewhere")] = \
            buckets.get(hit or ("zero" if val == 0 else "elsewhere"), 0) + 1
    print(f"got entries by destination: {buckets}")
    print("first 12 entries:", [hex(x) for x in vals[:12]])

# 3. Find the instructions that build the address, whatever form they take.
text = v.section(".text")
md = capstone.Cs(capstone.CS_ARCH_MIPS,
                 capstone.CS_MODE_MIPS32 |
                 (capstone.CS_MODE_LITTLE_ENDIAN if v.little
                  else capstone.CS_MODE_BIG_ENDIAN))
ins = list(md.disasm(data[text.offset:text.offset + text.size], text.addr))

hi16, lo16 = (target >> 16) & 0xFFFF, target & 0xFFFF
hi_adj = (hi16 + 1) & 0xFFFF          # when the low half is sign-extended
cands = []
for i, x in enumerate(ins):
    if x.mnemonic == "lui" and (hex(hi16) in x.op_str or hex(hi_adj) in x.op_str
                                or str(hi16) in x.op_str.split(",")[-1].strip()):
        cands.append(i)
    elif x.mnemonic in ("addiu", "ori", "lw", "sw") and (
            hex(lo16) in x.op_str or hex(lo16 - 0x10000) in x.op_str):
        cands.append(i)

print(f"\n{len(cands)} instruction(s) mention the high or low half:")
seen = set()
for i in cands[:6]:
    lo, hi = max(0, i - 3), min(len(ins), i + 4)
    if (lo, hi) in seen:
        continue
    seen.add((lo, hi))
    print(f"  --- around {hex(ins[i].address)}")
    for x in ins[lo:hi]:
        mark = ">>" if x.address == ins[i].address else "  "
        print(f"   {mark} {hex(x.address)}  {x.mnemonic:<8} {x.op_str}")
