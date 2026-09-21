"""
sentinel.firmware.analyzers.sharedkeys
======================================

Connecting the front end to the back end.

Every analyzer so far looks at one artefact in isolation. The web root is
HTML and JavaScript; the binaries are ELF. But an embedded device's front end
and back end have to agree on parameter names — the form field the browser
posts is the string the CGI binary looks up — and that agreement is visible
in both files as the same literal text.

This is the observation behind SaTC (Chen et al., "Sharing More and Checking
Less: Leveraging Common Input Keywords to Detect Bugs in Embedded Systems",
USENIX Security 2021). Full taint analysis across a stripped MIPS binary is
expensive and fragile; the shared keyword is a cheap proxy that says *where*
to look. A parameter name found in both the web root and a binary marks the
exact boundary where untrusted input crosses into native code.

What this produces, concretely, on a router image:

    bin/httpd shares 43 parameter names with the web UI, builds shell
    commands from format strings, and `wanIp` sits 112 bytes from
    "echo %s >> %s" in .rodata

That last clause is the finding. Two strings adjacent in .rodata are usually
referenced by the same function — the compiler emits them in source order —
so a parameter name next to a command template is the shape of an injection
that has not been proven yet but can be, in one sitting, with a disassembler.

It stays on the presence axis and never reaches confirmed. Adjacency in
.rodata is evidence about the *source file*, not about dataflow. Two strings
can share a function and never touch each other. Claiming otherwise would put
a confirmed finding on a layout coincidence.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)
from ..models import RootFS
from .binanalysis import extract_templates, parse_elf, Template

# --------------------------------------------------------------------------
# Front-end keyword extraction
# --------------------------------------------------------------------------

WEB_EXT_RE = re.compile(r"\.(html?|js|asp|php|cgi|xml|json)$", re.I)
WEB_DIR_RE = re.compile(r"(?:^|/)(?:www|web|webroot|htdocs|html|cgi-bin)[^/]*/")

# How a parameter name appears in a front end. Each pattern is one way the
# browser side names a value it will send.
KEYWORD_PATTERNS = [
    re.compile(rb"""<input[^>]*\sname\s*=\s*["']([A-Za-z_][\w.\-]{2,40})["']""", re.I),
    re.compile(rb"""<select[^>]*\sname\s*=\s*["']([A-Za-z_][\w.\-]{2,40})["']""", re.I),
    re.compile(rb"""<textarea[^>]*\sname\s*=\s*["']([A-Za-z_][\w.\-]{2,40})["']""", re.I),
    re.compile(rb"""getElementById\(\s*["']([A-Za-z_][\w.\-]{2,40})["']"""),
    re.compile(rb"""[?&]([A-Za-z_][\w.\-]{2,40})=""" ),
    re.compile(rb"""["']([A-Za-z_][\w.\-]{2,40})["']\s*:\s*[\w$"']"""),
    re.compile(rb"""\.(?:val|value)\s*\(\s*\)\s*;?\s*//?\s*([A-Za-z_][\w.\-]{2,40})"""),
    re.compile(rb"""(?:data|params)\[["']([A-Za-z_][\w.\-]{2,40})["']\]"""),
]

# Words that appear in every web page ever written and carry no information
# about this device. Filtering them is what keeps the intersection meaningful.
STOPWORDS = {
    "value", "name", "type", "text", "class", "style", "href", "src", "div",
    "span", "form", "input", "button", "submit", "table", "width", "height",
    "color", "title", "index", "html", "head", "body", "script", "function",
    "return", "length", "string", "number", "object", "array", "true",
    "false", "null", "undefined", "window", "document", "console", "error",
    "data", "json", "http", "https", "content", "charset", "utf", "get",
    "post", "url", "uri", "path", "file", "list", "item", "option", "label",
    "checked", "selected", "disabled", "readonly", "placeholder", "onclick",
    "onchange", "onload", "onsubmit", "display", "none", "block", "hidden",
    "left", "right", "top", "bottom", "center", "margin", "padding", "border",
    "background", "font", "size", "align", "valign", "colspan", "rowspan",
    "and", "the", "for", "var", "let", "const", "this", "self", "new",
    # Words that are real form values but carry no device meaning, and that
    # collide with unrelated strings in every binary on the system. `auto`
    # matched a busybox mount option and put tar, ash, ps and getopt in the
    # report.
    "auto", "manual", "enable", "enabled", "disable", "disabled", "mode",
    "state", "status", "start", "stop", "restart", "reset", "apply",
    "cancel", "save", "close", "open", "edit", "delete", "remove", "add",
    "yes", "test", "temp", "info", "help", "home", "back", "next", "prev",
    "page", "line", "row", "col", "min", "max", "low", "high", "count",
    "total", "level", "group", "order", "sort", "filter", "search", "query",
    "result", "message", "warning", "success", "failed", "failure", "empty",
    "flag", "step", "range", "unit", "scale", "offset", "buffer", "entry",
}

MIN_KEYWORD_LEN = 4


@dataclass
class Keyword:
    name: str
    sources: set[str] = field(default_factory=set)

    @property
    def interesting(self) -> bool:
        """
        Names that tend to carry values reaching a shell.

        Not a filter — every shared keyword is reported. This only promotes
        ordering, because a parameter called `pingAddr` deserves attention
        before one called `showAdvanced`.
        """
        n = self.name.lower()
        return any(h in n for h in (
            "addr", "ip", "host", "url", "path", "file", "name", "cmd",
            "ping", "trace", "dns", "server", "user", "pass", "key", "ssid",
            "mac", "port", "iface", "if", "wan", "lan", "route", "gateway",
            "time", "ntp", "upload", "backup", "restore", "firmware", "exec",
        ))


def extract_frontend_keywords(rootfs: RootFS,
                              max_files: int = 400) -> dict[str, Keyword]:
    """Parameter names the browser side knows about."""
    found: dict[str, Keyword] = {}
    seen = 0
    for entry in rootfs.walk(max_size=4 << 20):
        if seen >= max_files:
            break
        if not (WEB_EXT_RE.search(entry.rel) or WEB_DIR_RE.search(entry.rel)):
            continue
        try:
            data = entry.abspath.read_bytes()
        except OSError:
            continue
        seen += 1
        for pat in KEYWORD_PATTERNS:
            for m in pat.finditer(data):
                name = m.group(1).decode("utf-8", "replace")
                low = name.lower()
                if len(name) < MIN_KEYWORD_LEN or low in STOPWORDS:
                    continue
                if name.isdigit() or not re.match(r"^[A-Za-z_]", name):
                    continue
                found.setdefault(name, Keyword(name)).sources.add(entry.rel)
    return found


# --------------------------------------------------------------------------
# Back-end string extraction and correlation
# --------------------------------------------------------------------------

BIN_STRING_RE = re.compile(rb"[\x20-\x7e]{4,80}")


def binary_strings(data: bytes, view) -> dict[str, int]:
    """Strings in .rodata with their file offsets."""
    ro = view.section(".rodata") if view else None
    blob = data[ro.offset:ro.offset + ro.size] if ro else data
    base = ro.offset if ro else 0
    out: dict[str, int] = {}
    for m in BIN_STRING_RE.finditer(blob):
        s = m.group(0).decode("utf-8", "replace")
        out.setdefault(s, base + m.start())
    return out


@dataclass
class Correlation:
    binary: str
    shared: list[str]
    templates: list[Template]
    adjacencies: list[tuple[str, str, int]]   # keyword, template text, distance

    @property
    def score(self) -> int:
        s = min(len(self.shared), 60)
        s += len(self.templates) * 3
        s += len(self.adjacencies) * 12          # the actual signal
        return s


ADJACENCY_WINDOW = 512


def correlate(keywords: dict[str, Keyword], rel: str, data: bytes
              ) -> Optional[Correlation]:
    view = parse_elf(data)
    if view is None:
        return None
    strings = binary_strings(data, view)
    if not strings:
        return None

    # Exact string equality only. A substring match ("ip" inside "script")
    # would flood the intersection with noise and destroy the one property
    # that makes this technique worth anything.
    shared = [k for k in keywords if k in strings]
    if not shared:
        return None

    templates = extract_templates(view)
    adjacencies: list[tuple[str, str, int]] = []
    for t in templates:
        for k in shared:
            dist = abs(strings[k] - t.offset)
            if dist <= ADJACENCY_WINDOW:
                adjacencies.append((k, t.text[:100], dist))
    adjacencies.sort(key=lambda a: a[2])

    return Correlation(rel, sorted(shared), templates, adjacencies)


# --------------------------------------------------------------------------
# Detector
# --------------------------------------------------------------------------

class SharedKeywordDetector:
    meta = DetectorMeta(
        id="fw.binary.shared_keywords",
        name="Web parameter names reaching native code",
        severity=Severity.MEDIUM,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-78",
        owasp="A03:2021",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["taint", "triage", "command-injection", "satc"],
    )

    def __init__(self, min_shared: int = 3, max_binaries: int = 80):
        self.min_shared = min_shared
        self.max_binaries = max_binaries

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        keywords = extract_frontend_keywords(subject)
        if len(keywords) < 5:
            return                  # no front end worth correlating against

        results: list[tuple[Correlation, bytes]] = []
        by_content: dict[str, str] = {}      # sha256 -> first path seen
        aliases: dict[str, list[str]] = {}   # first path -> other names
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
            examined += 1

            # Busybox ships one binary under a dozen applet names, and
            # vendors rebuild the same daemon as dhcpcd_wan1..wan4. Reporting
            # each copy separately turns one finding into ten and buries the
            # distinct ones. Correlate once per distinct content.
            digest = hashlib.sha256(data).hexdigest()
            if digest in by_content:
                aliases.setdefault(by_content[digest], []).append(entry.rel)
                continue
            by_content[digest] = entry.rel

            c = correlate(keywords, entry.rel, data)
            if c and len(c.shared) >= self.min_shared:
                results.append((c, data))

        results.sort(key=lambda r: -r[0].score)

        for c, data in results[:12]:
            hot = [k for k in c.shared if keywords[k].interesting]
            blob = ctx.store_blob(c.binary.replace("/", "_"), data[:4 << 20])

            same = aliases.get(c.binary, [])
            if c.adjacencies:
                kw, tmpl, dist = c.adjacencies[0]
                needle = kw.encode()
                view = parse_elf(data)
                off = binary_strings(data, view).get(kw, 0)
                sev = Severity.HIGH
                headline = (f"{c.binary}: web parameter {kw!r} sits {dist} "
                            f"bytes from {tmpl[:60]!r} in .rodata"
                            + (f" (+{len(same)} identical copies)" if same else ""))
            else:
                needle = c.shared[0].encode()
                view = parse_elf(data)
                off = binary_strings(data, view).get(c.shared[0], 0)
                sev = Severity.MEDIUM if hot else Severity.LOW
                headline = (f"{c.binary} handles {len(c.shared)} parameter "
                            f"names from the web UI")

            proof = ProofArtifact(
                kind="byte_match",
                claim={"blob": blob,
                       "file_sha256": hashlib.sha256(data[:4 << 20]).hexdigest(),
                       "offset": off, "length": len(needle),
                       "needle_sha256": hashlib.sha256(needle).hexdigest()},
                blobs=[blob],
            )

            f = Finding(
                detector_id=self.meta.id,
                title=headline,
                severity=sev,
                axis=Axis.PRESENCE,
                target=c.binary,
                summary=(
                    f"{len(c.shared)} parameter names appear in both the web "
                    f"root and this binary, which marks where browser input "
                    f"crosses into native code. "
                    + (f"{len(c.adjacencies)} of them sit within "
                       f"{ADJACENCY_WINDOW} bytes of a shell command template "
                       f"in .rodata — strings that close together are usually "
                       f"emitted by the same function, so this is where to "
                       f"start tracing. Adjacency is evidence about source "
                       f"layout, not about dataflow: only the disassembly "
                       f"shows whether the parameter reaches the template."
                       if c.adjacencies else
                       "No parameter sits near a command template, so this "
                       "binary handles web input but shows no obvious shell "
                       "sink beside it.")
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                owasp=self.meta.owasp,
                context={
                    "locus": {"file": c.binary},
                    "shared_count": len(c.shared),
                    "shared_sample": c.shared[:30],
                    "interesting_params": hot[:20],
                    "adjacencies": [
                        {"param": k, "template": t, "distance": d}
                        for k, t, d in c.adjacencies[:10]],
                    "frontend_sources": sorted(
                        {s for k in c.shared[:10] for s in keywords[k].sources}
                    )[:8],
                    "next_step": ("xref the parameter string in a "
                                  "disassembler and follow it to the sink"),
                    "identical_copies": aliases.get(c.binary, [])[:12],
                },
                triage_notes=["shared keywords locate the input boundary; "
                              "they do not prove dataflow"],
            )
            try:
                f.confirm(proof, ctx.artifact_root)
                f.confidence = Confidence.PROBABLE   # never more than this
            except Exception:
                pass
            yield f


DETECTORS = [SharedKeywordDetector()]

__all__ = ["SharedKeywordDetector", "extract_frontend_keywords", "correlate",
           "Correlation", "Keyword", "DETECTORS"]
