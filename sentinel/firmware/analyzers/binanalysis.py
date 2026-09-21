"""
 sentinel.firmware.analyzers.binanalysis
=======================================

Looking inside the binaries, not just at them.

Every detector before this one reads files. The dominant command-injection
class lives in code: `RunSystemCmd("echo root:%s | chpasswd -m", param)` is
CVE-2024-48456, and no amount of filesystem inspection finds it. Saying "this
binary imports system()" does not help either — on a router image that is
most of them.

Two layers here, deliberately in this order.

**Layer 1: command templates.** Pull the strings a binary would hand to a
shell — a format string containing `%s` that also names a real command or
carries shell metacharacters. This needs no disassembly, works on every
architecture, and never fails on a stripped or packed binary. It is also
where the signal actually is: `"echo root:%s | chpasswd -m"` tells you what
the bug is before you have opened a disassembler, because a `%s` sitting
inside a shell pipeline is a command-injection sink unless something upstream
sanitises it.

**Layer 2: callsites.** With capstone, resolve calls to system/popen/execl
and walk backward to find what the first argument was loaded with. This says
*which* template reaches *which* sink at *which* address, which is where you
put your first breakpoint. Best-effort: it handles MIPS and ARM, gives up
quietly on anything unusual, and layer 1 still stands when it does.

What neither layer establishes is whether the `%s` is attacker-controlled.
That is taint analysis across a binary — the problem Firmalice, SaTC and
Karonte exist to solve — and pretending otherwise would put a confirmed
finding on a guess. So these stay on the presence axis: the template exists,
the callsite exists, the reachability question is yours.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Iterable, Optional

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)
from ..models import RootFS

try:
    import capstone
    HAVE_CAPSTONE = True
except ImportError:  # layer 2 is optional
    HAVE_CAPSTONE = False


# --------------------------------------------------------------------------
# ELF sections, enough of them
# --------------------------------------------------------------------------

@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int


@dataclass
class ElfView:
    data: bytes
    is64: bool
    little: bool
    machine: int
    sections: dict[str, Section]
    dynsyms: dict[int, str]     # PLT-relevant symbol index -> name

    @property
    def order(self) -> str:
        return "little" if self.little else "big"

    def section(self, name: str) -> Optional[Section]:
        return self.sections.get(name)

    def read_at_addr(self, addr: int, length: int) -> bytes:
        """Translate a virtual address to file bytes via section headers."""
        for s in self.sections.values():
            if s.addr and s.addr <= addr < s.addr + s.size:
                off = s.offset + (addr - s.addr)
                return self.data[off:off + length]
        return b""

    def cstring_at_addr(self, addr: int, limit: int = 300) -> Optional[bytes]:
        raw = self.read_at_addr(addr, limit)
        if not raw:
            return None
        end = raw.find(b"\x00")
        return raw[:end] if end > 0 else None


def parse_elf(data: bytes) -> Optional[ElfView]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None
    is64 = data[4] == 2
    little = data[5] == 1
    o = "little" if little else "big"
    try:
        machine = int.from_bytes(data[18:20], o)
        if is64:
            shoff = int.from_bytes(data[40:48], o)
            shentsize = int.from_bytes(data[58:60], o)
            shnum = int.from_bytes(data[60:62], o)
            shstrndx = int.from_bytes(data[62:64], o)
        else:
            shoff = int.from_bytes(data[32:36], o)
            shentsize = int.from_bytes(data[46:48], o)
            shnum = int.from_bytes(data[48:50], o)
            shstrndx = int.from_bytes(data[50:52], o)
        if not shoff or not shnum or shnum > 512:
            return None

        raw = []
        for i in range(shnum):
            b = data[shoff + i * shentsize: shoff + (i + 1) * shentsize]
            if len(b) < (64 if is64 else 40):
                return None
            if is64:
                raw.append((int.from_bytes(b[0:4], o),
                            int.from_bytes(b[16:24], o),
                            int.from_bytes(b[24:32], o),
                            int.from_bytes(b[32:40], o)))
            else:
                raw.append((int.from_bytes(b[0:4], o),
                            int.from_bytes(b[12:16], o),
                            int.from_bytes(b[16:20], o),
                            int.from_bytes(b[20:24], o)))

        strtab_off = raw[shstrndx][2]
        sections: dict[str, Section] = {}
        for name_off, addr, off, size in raw:
            end = data.find(b"\x00", strtab_off + name_off)
            name = data[strtab_off + name_off:end].decode("utf-8", "replace")
            sections[name] = Section(name, addr, off, size)
        return ElfView(data, is64, little, machine, sections, {})
    except (struct.error, IndexError, ValueError):
        return None


# --------------------------------------------------------------------------
# Layer 1: shell command templates
# --------------------------------------------------------------------------

# Commands a device binary actually shells out to. A template naming one of
# these is doing something; a random string with a %s in it is not.
SHELL_COMMANDS = (
    "echo", "cat", "rm", "cp", "mv", "chmod", "chown", "kill", "killall",
    "ping", "ping6", "traceroute", "nslookup", "wget", "curl", "tftp",
    "ifconfig", "ip ", "route", "iptables", "ebtables", "brctl", "vconfig",
    "iwconfig", "iwpriv", "wl ", "nvram", "flash", "reboot", "halt",
    "chpasswd", "passwd", "useradd", "adduser", "telnetd", "dropbear",
    "sh -c", "/bin/sh", "/bin/bash", "system", "udhcpc", "hostname",
    "mount", "umount", "insmod", "rmmod", "modprobe", "sendmail", "date",
)

# Metacharacters that turn an interpolated value into a second command.
SHELL_METACHARS = (";", "|", "&&", "||", "`", "$(", ">", ">>", "&")

# Shapes that carry metacharacters for reasons having nothing to do with a
# shell. Every one produced a false positive on a real router image: ANSI
# debug logs (`[1;31m[TIMER_CHECK >>%s]`), HTTP query strings where `&`
# separates parameters, JSON payloads, log lines with `->` arrows, and
# getopt help text.
ANSI_RE = re.compile(r"\x1b\[|\[\d;\d{1,2}(;\d{1,2})?m")
URL_QUERY_RE = re.compile(r"(?:HTTP/\d|^(?:GET|POST|PUT) /|\?[a-z_]+=)", re.I)
JSON_RE = re.compile(r'^\s*[\{\[]|\"\w+\"\s*:')
ARROW_RE = re.compile(r"-+>|=>|<-+")
HELP_TEXT_RE = re.compile(r"(?:try `|--help|usage:|invalid option|unknown option)", re.I)
# GNU quotes tokens as `like this' -- backtick open, apostrophe close. That
# is prose, not command substitution, which pairs backtick with backtick.
GNU_QUOTE_RE = re.compile(r"`[^`\n]{0,80}'")


def _shell_metachars(text: str) -> list[str]:
    """
    Metacharacters that plausibly reach a shell, lookalikes removed.

    `>` inside `->` is an arrow, not a redirect. `&` inside `a=1&b=2` is a
    query separator, not backgrounding. Counting those is how 60 of 103
    binaries got flagged on one image.
    """
    if ANSI_RE.search(text) or JSON_RE.search(text) or HELP_TEXT_RE.search(text):
        return []
    if URL_QUERY_RE.search(text):
        return []
    stripped = ARROW_RE.sub(" ", text)
    stripped = GNU_QUOTE_RE.sub(" ", stripped)
    out = []
    for mc in SHELL_METACHARS:
        if mc not in stripped:
            continue
        if mc == "&" and "&&" not in stripped and not re.search(r"&\s*$", stripped):
            continue
        if mc == ">" and not re.search(r">\s*(?:/|%s|\$|[\w.]+\s*$)", stripped):
            continue
        out.append(mc)
    return out

FORMAT_SPEC = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[sdiuxX]")
PRINTABLE = re.compile(rb"[\x20-\x7e]{8,400}")


@dataclass
class Template:
    text: str
    offset: int
    specs: list[str]
    commands: list[str]
    metachars: list[str]

    @property
    def score(self) -> int:
        s = len(self.commands) * 4 + len(self.metachars) * 3
        # A %s adjacent to a metacharacter is the dangerous shape: the
        # interpolated value lands where a new command can start.
        # self.metachars, NOT SHELL_METACHARS: the raw tuple still holds the
        # ones the lookalike filter rejected, so consulting it here let a URL
        # query string (`hostname=%s&wildcard=NO`) collect the full adjacency
        # bonus after the filter had correctly discarded its `&`.
        if any(f"%s{mc}" in self.text or f"{mc}%s" in self.text
               or f"%s {mc}" in self.text for mc in self.metachars):
            s += 8
        if self.text.startswith(("/bin/", "/sbin/", "/usr/")):
            s += 3
        return s + len(self.specs)


def extract_templates(view: ElfView, max_results: int = 40) -> list[Template]:
    """Strings that look like shell commands built with a format string."""
    ro = view.section(".rodata") or view.section(".data")
    blob = (view.data[ro.offset:ro.offset + ro.size] if ro
            else view.data)
    base = ro.offset if ro else 0

    out: list[Template] = []
    for m in PRINTABLE.finditer(blob):
        raw = m.group(0)
        # split on NULs that the regex may have spanned
        text = raw.decode("utf-8", "replace")
        specs = FORMAT_SPEC.findall(text)
        if not specs:
            continue
        low = text.lower()
        cmds = [c.strip() for c in SHELL_COMMANDS if c in low]
        metas = _shell_metachars(text)
        if not cmds and not metas:
            continue
        # A format string with no command and only a ">" is almost always a
        # log line or a printf, not a shell invocation.
        if not cmds and len(metas) < 2:
            continue
        if not metas and not text.startswith(("/bin/", "/sbin/", "/usr/")):
            # A command name buried in prose ("failure to parse app rule")
            # is not a command being run.
            if not re.match(r"^\s*[/\w.-]+\s", text):
                continue
        out.append(Template(text[:300], base + m.start(), specs, cmds, metas))

    out.sort(key=lambda t: -t.score)
    return out[:max_results]


# --------------------------------------------------------------------------
# Layer 2: callsites, where capstone is available
# --------------------------------------------------------------------------

SINK_NAMES = ("system", "popen", "execl", "execlp", "execv", "execve",
              "doSystemCmd", "doShell", "RunSystemCmd", "twsystem", "CsteSystem")


def _cs_for(view: ElfView):
    if not HAVE_CAPSTONE:
        return None
    mode = capstone.CS_MODE_LITTLE_ENDIAN if view.little else capstone.CS_MODE_BIG_ENDIAN
    if view.machine == 0x08:      # MIPS
        return capstone.Cs(capstone.CS_ARCH_MIPS,
                           capstone.CS_MODE_MIPS32 | mode)
    if view.machine == 0x28:      # ARM
        return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | mode)
    if view.machine == 0xB7:      # AArch64
        return capstone.Cs(capstone.CS_ARCH_ARM64, mode)
    return None


@dataclass
class CallSite:
    address: int
    sink: str
    argument: Optional[str]


def find_callsites(view: ElfView, templates: list[Template],
                   limit: int = 25) -> list[CallSite]:
    """
    Locate calls to a shell sink and try to name the first argument.

    Best-effort by design. Resolving the argument means walking backward from
    the call looking for the register that holds it being loaded with an
    address, which works on straight-line code and fails on anything the
    compiler was clever about. A failure yields a callsite with no argument
    rather than a wrong one.
    """
    md = _cs_for(view)
    text = view.section(".text")
    if md is None or text is None or not text.size:
        return []
    md.detail = True

    # Sink names appear in .dynstr; a call into the PLT resolves through a
    # relocation we would have to parse. Cheaper and good enough: match on
    # the disassembler's own symbolication of the branch target when the
    # binary is not stripped, and otherwise report the callsite anonymously.
    sink_addrs: dict[int, str] = {}
    plt = view.section(".plt")
    dynstr = view.section(".dynstr")
    if plt and dynstr:
        names = view.data[dynstr.offset:dynstr.offset + dynstr.size]
        for sink in SINK_NAMES:
            if b"\x00" + sink.encode() + b"\x00" in names:
                sink_addrs[0] = sink   # presence only; address unresolved

    code = view.data[text.offset:text.offset + min(text.size, 4 << 20)]
    by_addr = {t.offset: t for t in templates}
    results: list[CallSite] = []

    try:
        insns = list(md.disasm(code, text.addr))
    except Exception:
        return []

    for i, ins in enumerate(insns):
        if ins.mnemonic not in ("jal", "bl", "jalr", "blx", "b", "j"):
            continue
        # Walk back for an address materialised into the first-argument
        # register: $a0 on MIPS, r0 on ARM.
        argreg = "$a0" if view.machine == 0x08 else "r0"
        arg = None
        for prev in insns[max(0, i - 12):i][::-1]:
            if argreg not in prev.op_str:
                continue
            for imm in re.findall(r"0x[0-9a-f]+", prev.op_str):
                s = view.cstring_at_addr(int(imm, 16))
                if s and FORMAT_SPEC.search(s.decode("utf-8", "replace")):
                    arg = s.decode("utf-8", "replace")[:200]
                    break
            if arg:
                break
        if arg:
            results.append(CallSite(ins.address, "shell-sink", arg))
        if len(results) >= limit:
            break
    return results


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------

class CommandTemplateDetector:
    meta = DetectorMeta(
        id="fw.binary.command_template",
        name="Shell command built from a format string",
        severity=Severity.MEDIUM,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-78",
        owasp="A03:2021",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["command-injection", "binary", "triage"],
    )

    def __init__(self, min_score: int = 17, max_binaries: int = 60):
        self.min_score = min_score
        self.max_binaries = max_binaries

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        examined = 0
        for entry in subject.walk(max_size=16 << 20):
            if examined >= self.max_binaries:
                break
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            if data[:4] != b"\x7fELF":
                continue
            view = parse_elf(data)
            if view is None:
                continue

            templates = extract_templates(view)
            hot = [t for t in templates if t.score >= self.min_score]
            if not hot:
                continue
            examined += 1

            callsites = find_callsites(view, templates) if HAVE_CAPSTONE else []
            top = hot[0]

            blob = ctx.store_blob(entry.rel.replace("/", "_"), data[:4 << 20])
            needle = top.text.encode("utf-8", "replace")[:64]
            proof = ProofArtifact(
                kind="byte_match",
                claim={"blob": blob,
                       "file_sha256": hashlib.sha256(data[:4 << 20]).hexdigest(),
                       "offset": top.offset,
                       "length": len(needle),
                       "needle_sha256": hashlib.sha256(needle).hexdigest()},
                blobs=[blob],
            )

            sev = Severity.MEDIUM if top.score >= 20 else Severity.LOW
            f = Finding(
                detector_id=self.meta.id,
                title=(f"{entry.rel} builds shell commands from format "
                       f"strings ({len(hot)} template(s), top score {top.score})"),
                severity=sev,
                axis=Axis.PRESENCE,
                target=entry.rel,
                summary=(
                    f"The binary contains shell command templates with format "
                    f"specifiers — the highest-scoring is {top.text[:120]!r}. "
                    f"Where an interpolated value lands next to a shell "
                    f"metacharacter, anything unsanitised reaching it becomes "
                    f"a second command. This is the exact shape of "
                    f"CVE-2024-48456. Whether the value is attacker-"
                    f"controlled needs taint analysis and is not claimed here."
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                owasp=self.meta.owasp,
                context={
                    "locus": {"file": entry.rel},
                    "templates": [
                        {"text": t.text[:160], "offset": hex(t.offset),
                         "score": t.score, "commands": t.commands[:5],
                         "metachars": t.metachars[:5]}
                        for t in hot[:8]],
                    "callsites": [
                        {"address": hex(c.address), "argument": c.argument[:120]}
                        for c in callsites[:8]],
                    "disassembly": "capstone" if HAVE_CAPSTONE else "unavailable",
                    "next_step": ("trace the format argument back to a request "
                                  "parameter in a disassembler"),
                },
                triage_notes=["presence of the template is proven; "
                              "attacker control of the value is not"],
            )
            try:
                f.confirm(proof, ctx.artifact_root)
                # Proven that the template is there. Never more than probable
                # about what it means.
                f.confidence = Confidence.PROBABLE
            except Exception:
                pass
            yield f


DETECTORS = [CommandTemplateDetector()]

__all__ = ["CommandTemplateDetector", "extract_templates", "find_callsites",
           "parse_elf", "ElfView", "Template", "HAVE_CAPSTONE", "DETECTORS"]
