"""
sentinel.firmware.analyzers.xref
================================

From "these strings are near each other" to "this function uses both".

`sharedkeys` reports adjacency in `.rodata`: a web parameter name sitting a
few bytes from a shell command template. That is a layout fact. Compilers
emit string literals roughly in source order, so adjacency suggests the same
routine — but it is a suggestion, and two literals can share a translation
unit while living in functions that never call each other.

This module closes that gap by reading the code. A string is only used if an
instruction materialises its address, so finding those instructions and
grouping them by enclosing function turns a layout coincidence into a
statement about control flow: *this* function, at *this* address, references
both the parameter name and the command template.

That is the difference between "worth a look" and "open Ghidra at 0x404f80".

How the addresses are recovered
-------------------------------
MIPS has no 32-bit immediate, so an address arrives in two halves:

    lui   $a1, 0x42          # upper 16 bits
    addiu $a1, $a1, -0x6f30  # lower 16, sign-extended

The pair must be reassembled with the sign extension applied, which is the
detail that makes a naive `lui`-only scan produce addresses that are off by
64KB roughly half the time. The two halves are usually adjacent but the
compiler is free to schedule other instructions between them, so a small
window is searched.

ARM materialises addresses from a PC-relative literal pool, which capstone
resolves for us, so that path is simpler and correspondingly less tested.

Function boundaries without symbols
-----------------------------------
Vendor binaries are stripped. MIPS O32 has a recognisable shape, though:
a function opens by making stack room (`addiu $sp, $sp, -N`) and returns
with `jr $ra`. Scanning for those gives boundaries that are right often
enough to group references, and where they are wrong the failure is benign —
two references land in different buckets and the finding is simply not
raised, rather than a wrong one being raised.

Everything here stays on the presence axis. Proving a function references
both strings is not proving the parameter's value reaches the command; the
function could sanitise it, or use them on unrelated paths. It tells you
which function to read, with an address.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from .binanalysis import ElfView, parse_elf

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

EM_MIPS, EM_ARM, EM_AARCH64 = 0x08, 0x28, 0xB7


@dataclass
class Function:
    start: int
    end: int
    refs: dict[int, list[int]] = field(default_factory=dict)  # target -> ins addrs

    @property
    def size(self) -> int:
        return self.end - self.start


@dataclass
class XrefResult:
    functions: list[Function]
    disassembled: int
    note: str = ""

    def referencing(self, *targets: int) -> list[Function]:
        """Functions that reference every one of the given addresses."""
        want = set(targets)
        return [f for f in self.functions if want <= set(f.refs)]


# --------------------------------------------------------------------------

def _cs(view: ElfView):
    if not HAVE_CAPSTONE:
        return None
    endian = (capstone.CS_MODE_LITTLE_ENDIAN if view.little
              else capstone.CS_MODE_BIG_ENDIAN)
    if view.machine == EM_MIPS:
        return capstone.Cs(capstone.CS_ARCH_MIPS,
                           capstone.CS_MODE_MIPS32 | endian)
    if view.machine == EM_ARM:
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian)
    if view.machine == EM_AARCH64:
        return capstone.Cs(capstone.CS_ARCH_ARM64, endian)
    return None


# Capstone renders immediates in hex when they are large and in plain
# decimal when they are small, so `addiu $a0, $a0, 8` and
# `addiu $a0, $a0, 0x4f30` both occur. Matching only the hex form silently
# dropped every reference whose low half happened to be under 10.
_IMM = re.compile(r"(-?)(?:0x([0-9a-fA-F]+)|(\d+))\s*$")


def _imm(op_str: str) -> Optional[int]:
    m = _IMM.search(op_str.strip().rstrip(")"))
    if not m:
        return None
    v = int(m.group(2), 16) if m.group(2) else int(m.group(3))
    return -v if m.group(1) == "-" else v


def _reg(op_str: str) -> Optional[str]:
    m = re.match(r"\s*(\$\w+|r\d+|[wx]\d+)", op_str)
    return m.group(1) if m else None


LUI_WINDOW = 8          # instructions a lui/addiu pair may be split across

# MIPS ABI: $gp points 0x7ff0 past the start of the GOT, so a PIC binary
# reaches a string with `lw $v0, -0x7fd8($gp)` and the GOT entry at that
# index holds the real address. Vendor daemons are almost always PIC, which
# means a resolver that only understands lui/addiu finds nothing at all on
# the binaries that matter -- it reports zero references and looks like a
# clean result.
GP_BIAS = 0x7FF0


def _got_table(view: ElfView) -> dict[int, int]:
    """GOT entry virtual address -> the address stored in it."""
    got = view.section(".got")
    if got is None or not got.addr:
        return {}
    raw = view.data[got.offset:got.offset + got.size]
    order = "little" if view.little else "big"
    step = 8 if view.is64 else 4
    out: dict[int, int] = {}
    for i in range(0, len(raw) - step + 1, step):
        out[got.addr + i] = int.from_bytes(raw[i:i + step], order)
    return out


def _gp_value(view: ElfView) -> Optional[int]:
    got = view.section(".got")
    return (got.addr + GP_BIAS) if (got is not None and got.addr) else None


def resolve_string_refs(view: ElfView, targets: set[int],
                        max_bytes: int = 8 << 20) -> XrefResult:
    """
    Find every instruction that materialises one of `targets`, grouped by
    the function containing it.

    `targets` are virtual addresses of strings, which callers get from the
    `.rodata` section header plus the string's file offset.
    """
    md = _cs(view)
    text = view.section(".text")
    if md is None or text is None or not text.size:
        return XrefResult([], 0, "no disassembler or no .text")
    md.detail = False

    code = view.data[text.offset:text.offset + min(text.size, max_bytes)]
    try:
        insns = list(md.disasm(code, text.addr))
    except Exception as exc:
        return XrefResult([], 0, f"disassembly failed: {exc}")
    if not insns:
        return XrefResult([], 0, "disassembler produced nothing")

    # -- function boundaries -------------------------------------------
    bounds: list[int] = [insns[0].address]
    for i, ins in enumerate(insns):
        if view.machine == EM_MIPS:
            # A stack-allocating prologue starts a function. `jr $ra`
            # ends one, and the next instruction after its delay slot
            # begins the next.
            if ins.mnemonic == "addiu" and ins.op_str.startswith("$sp, $sp, -"):
                bounds.append(ins.address)
            elif ins.mnemonic == "jr" and "$ra" in ins.op_str:
                if i + 2 < len(insns):
                    bounds.append(insns[i + 2].address)
        else:
            if ins.mnemonic in ("push", "stp") and ("lr" in ins.op_str
                                                    or "x30" in ins.op_str):
                bounds.append(ins.address)
    bounds = sorted(set(bounds))

    end_of_text = insns[-1].address + insns[-1].size
    funcs = [Function(start=b, end=(bounds[i + 1] if i + 1 < len(bounds)
                                    else end_of_text))
             for i, b in enumerate(bounds)]

    def owner(addr: int) -> Optional[Function]:
        lo, hi = 0, len(funcs) - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            f = funcs[mid]
            if addr < f.start:
                hi = mid - 1
            elif addr >= f.end:
                lo = mid + 1
            else:
                return f
        return None

    # -- address materialisation ----------------------------------------
    hits = 0
    if view.machine == EM_MIPS:
        # --- PIC: lw $reg, imm($gp) then optionally addiu $reg, $reg, imm
        got, gp = _got_table(view), _gp_value(view)
        if got and gp is not None:
            gp_pending: dict[str, tuple[int, int]] = {}   # reg -> (base, idx)
            for i, ins in enumerate(insns):
                if ins.mnemonic in ("lw", "ld") and "($gp)" in ins.op_str:
                    reg = _reg(ins.op_str)
                    off = _imm(ins.op_str.split(",", 1)[-1].split("(")[0])
                    if reg is None or off is None:
                        continue
                    base = got.get(gp + off)
                    if base is None:
                        continue
                    gp_pending[reg] = (base, i)
                    if base in targets:
                        f = owner(ins.address)
                        if f is not None:
                            f.refs.setdefault(base, []).append(ins.address)
                            hits += 1
                    continue
                if ins.mnemonic != "addiu":
                    continue
                reg = _reg(ins.op_str)
                if reg not in gp_pending:
                    continue
                base, idx = gp_pending[reg]
                if i - idx > LUI_WINDOW:
                    del gp_pending[reg]
                    continue
                lo = _imm(ins.op_str.split(",")[-1])
                if lo is None:
                    continue
                if lo > 0x7FFF:
                    lo -= 0x10000
                addr = (base + lo) & 0xFFFFFFFF
                del gp_pending[reg]
                if addr in targets:
                    f = owner(ins.address)
                    if f is not None:
                        f.refs.setdefault(addr, []).append(ins.address)
                        hits += 1

        # --- non-PIC: lui/addiu pair
        # lui gives the upper half; a later addiu/ori on the same register
        # supplies the lower. The addiu immediate is SIGNED -- ignoring that
        # puts the result 64KB out whenever the low half has bit 15 set,
        # which is about half the time.
        pending: dict[str, tuple[int, int, int]] = {}   # reg -> (hi, addr, idx)
        for i, ins in enumerate(insns):
            if ins.mnemonic == "lui":
                reg = _reg(ins.op_str)
                imm = _imm(ins.op_str.split(",", 1)[-1])
                if reg and imm is not None:
                    pending[reg] = (imm << 16, ins.address, i)
                continue
            if ins.mnemonic not in ("addiu", "ori", "addu"):
                continue
            reg = _reg(ins.op_str)
            if reg not in pending:
                continue
            hi, hi_addr, hi_idx = pending[reg]
            if i - hi_idx > LUI_WINDOW:
                del pending[reg]
                continue
            lo = _imm(ins.op_str.split(",")[-1])
            if lo is None:
                continue
            if ins.mnemonic == "addiu" and lo > 0x7FFF:
                lo -= 0x10000                      # sign extension
            addr = (hi + lo) & 0xFFFFFFFF
            del pending[reg]
            if addr in targets:
                f = owner(ins.address)
                if f is not None:
                    f.refs.setdefault(addr, []).append(ins.address)
                    hits += 1
    else:
        # ARM resolves PC-relative literals in the operand text.
        for ins in insns:
            if ins.mnemonic not in ("ldr", "adr", "adrp", "add"):
                continue
            imm = _imm(ins.op_str)
            if imm is None or imm not in targets:
                continue
            f = owner(ins.address)
            if f is not None:
                f.refs.setdefault(imm, []).append(ins.address)
                hits += 1

    live = [f for f in funcs if f.refs]
    return XrefResult(live, len(insns),
                      f"{len(insns)} instructions, {len(funcs)} functions, "
                      f"{hits} string references")


# --------------------------------------------------------------------------

def rodata_vaddr(view: ElfView, file_offset: int) -> Optional[int]:
    """Translate a .rodata file offset into the virtual address code uses."""
    ro = view.section(".rodata")
    if ro is None or not ro.addr:
        return None
    if not (ro.offset <= file_offset < ro.offset + ro.size):
        return None
    return ro.addr + (file_offset - ro.offset)


def correlate_in_code(data: bytes, offsets: dict[str, int]
                      ) -> list[tuple[list[str], int, dict[str, list[int]]]]:
    """
    Given {label: rodata file offset}, return the functions that reference
    two or more of them.

    Each result is (labels, function start address, {label: [instruction
    addresses]}) -- everything needed to open a disassembler at the right
    place and know what to look for when you get there.
    """
    view = parse_elf(data)
    if view is None:
        return []
    vaddr: dict[int, str] = {}
    for label, off in offsets.items():
        va = rodata_vaddr(view, off)
        if va is not None:
            vaddr[va] = label
    if len(vaddr) < 2:
        return []

    res = resolve_string_refs(view, set(vaddr))
    out = []
    for f in res.functions:
        labels = [vaddr[a] for a in f.refs if a in vaddr]
        if len(labels) < 2:
            continue
        where = {vaddr[a]: sites for a, sites in f.refs.items() if a in vaddr}
        out.append((sorted(labels), f.start, where))
    out.sort(key=lambda t: -len(t[0]))
    return out


__all__ = ["resolve_string_refs", "correlate_in_code", "rodata_vaddr",
           "XrefResult", "Function", "HAVE_CAPSTONE"]
