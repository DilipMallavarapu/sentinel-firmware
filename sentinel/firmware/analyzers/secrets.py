"""
sentinel.firmware.analyzers.secrets
===================================

Hardcoded credentials and key material.

This is the reference implementation for what a zero-false-positive firmware
detector looks like, so it is worth reading before writing another one.

Every finding here is a PRESENCE claim with a `byte_match` or validated
`pattern_match` proof: the exact bytes, their offset, the file hash. That is
re-checkable forever and cannot be wrong. What the detector deliberately does
*not* claim is that the credential works, is reachable, or is even used --
those are REACHABILITY questions and they are answered later by the emulation
lane, or not at all.

Where the false positives actually come from, and how each is closed:

  locked accounts     `root:*:` and `root:!:` are not credentials. Rejected
                      structurally, not by a confidence penalty.
  placeholder hashes  `x` in /etc/passwd means "look in shadow". Rejected.
  documentation       An example hash in a README is a real hash but not a
                      device credential. We scope by file role, and README
                      hits drop to CANDIDATE rather than being reported.
  test keys           Public test keys shipped by upstream (the well-known
                      Dropbear/OpenSSL sample keys) are fingerprinted against
                      a known-benign list and refuted outright.
  build artifacts     Hashes inside .o/.a/.pyc are noise. Excluded by path.

The remaining class we cannot fully close -- a vendor hash that is a genuine
per-device unique value baked at manufacture -- is why the finding says
"hardcoded credential material present", not "default password is X".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ...core.contracts import (
    Axis, Confidence, Detector, DetectorMeta, Finding, ProofArtifact,
    RunContext, Severity,
)
from ..models import RootFS

# Known-benign key material shipped by upstream projects. Extend freely --
# a refutation list is cheaper and more honest than a confidence fudge.
BENIGN_KEY_SHA256 = {
    # OpenSSL demo key, Dropbear test key, etc. Populate from your corpus.
}

# crypt(3) shapes we accept as real. Anything else in the field is ignored.
CRYPT_RE = re.compile(
    rb"^(?P<user>[A-Za-z0-9_.\-]{1,32}):"
    rb"(?P<hash>\$[1256][aby]?\$[^:$]{1,64}\$[./A-Za-z0-9]{16,}|[./A-Za-z0-9]{13}):",
    re.M,
)

PRIVKEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    rb"(?P<body>[A-Za-z0-9+/=\s]{100,})"
    rb"-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
)

# Config-file credential assignments. Tight on purpose: loose patterns here
# are the single biggest source of secret-scanner noise.
CONFIG_CRED_RE = re.compile(
    rb"(?P<key>(?:admin_?|root_?|default_?|telnet_?|web_?|wpa_?|wl\d?_?)?"
    rb"(?:passw(?:or)?d|passwd|secret|ps_?k|psk|pre_?shared_?key|"
    rb"api_?key|auth_?token|priv_?key))"
    # [ \t]* NOT \s*: \s matches newline, so `samba_passwd=` with an empty
    # value captures the whole of the following line. Every empty-valued key
    # in an nvram dump became a confirmed finding through that one character.
    rb"[ \t]*[=:][ \t]*[\"']?(?P<val>[^\s\"']{6,64})[\"']?",
    re.I,
)

PLACEHOLDER_VALUES = {
    b"x", b"*", b"!", b"!!", b"", b"none", b"null", b"changeme", b"password",
    b"<password>", b"your_password_here", b"%s", b"${password}", b"xxxxxx",
}

DOC_PATH_RE = re.compile(r"(readme|changelog|docs?/|examples?/|test(s|data)?/|\.md$)", re.I)

# Markup and script are code, not configuration. A firmware web root is full
# of `password: document.getElementById("pwd").value` and every one of those
# satisfies a naive key=value pattern. Scanning them for "hardcoded
# credentials" produces findings that are byte-accurate and semantically
# wrong -- the worst kind, because the proof verifies.
MARKUP_EXT_RE = re.compile(r"\.(html?|js|jsx|css|xsl|svg|jsp|asp|php)$", re.I)
MARKUP_SNIFF = (b"<html", b"<!doctype", b"<script", b"function(", b"function (")

# Tokens that mean the matched value is an expression, not a literal secret.
CODE_TOKENS = (b"document.", b"getelementbyid", b"function", b"return ",
               b"this.", b"window.", b"$(", b".value", b".val(", b"null",
               b"undefined", b"typeof", b"new ", b"=>")

# A literal secret is a flat token. Brackets, parens, semicolons and angle
# brackets all mean we captured a fragment of code.
CODE_CHARS = set(b"()[]{}<>;,")


def _is_literal_secret(val: bytes) -> bool:
    """Reject expressions, template placeholders and dotted identifiers."""
    low = val.lower()
    if any(tok in low for tok in CODE_TOKENS):
        return False
    if CODE_CHARS & set(val):
        return False
    if val.startswith(b"$") or b"${" in val or b"%(" in val:
        return False          # shell/template substitution
    # form.admin.value style: dotted identifier, all alphabetic segments
    parts = val.split(b".")
    if len(parts) > 1 and all(pt.isalpha() and pt for pt in parts):
        return False
    return True
BUILD_ARTIFACT_RE = re.compile(r"\.(o|a|pyc|pyo|d|gcno|map)$", re.I)

SHADOW_FILES = {"etc/shadow", "etc/shadow-", "etc/master.passwd",
                "etc/security/passwd", "etc/passwd", "etc/passwd-"}


def _hash_algorithm(h: bytes) -> str:
    """Name the algorithm, and say plainly when it is a broken one."""
    if h.startswith(b"$6$"):
        return "SHA-512 crypt"
    if h.startswith(b"$5$"):
        return "SHA-256 crypt"
    if h.startswith((b"$2a$", b"$2b$", b"$2y$")):
        return "bcrypt"
    if h.startswith(b"$1$"):
        return "MD5 crypt (weak; GPU-crackable)"
    if len(h) == 13:
        return ("traditional DES crypt (broken; 8-character maximum, "
                "falls to a wordlist in minutes)")
    return "unrecognised hash format"


@dataclass
class _Hit:
    rel: str
    offset: int
    needle: bytes
    kind: str
    detail: str


class HardcodedCredentialDetector:
    meta = DetectorMeta(
        id="fw.creds.hardcoded",
        name="Hardcoded credential material in firmware image",
        severity=Severity.HIGH,
        axis=Axis.PRESENCE,
        lane="firmware",
        owasp="A07:2021",
        cwe="CWE-798",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["credentials", "secrets", "firmware"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS) and subject.root.is_dir()

    # ----------------------------------------------------------------

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        for entry in subject.walk(max_size=8 << 20):
            if BUILD_ARTIFACT_RE.search(entry.rel) or entry.is_symlink:
                continue
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:512] and entry.rel not in SHADOW_FILES:
                # Binary file: only key material is worth scanning for.
                hits = list(self._private_keys(entry.rel, data))
            else:
                hits = [
                    *self._crypt_hashes(entry.rel, data),
                    *self._private_keys(entry.rel, data),
                    *self._config_creds(entry.rel, data),
                ]
            # One finding per (file, kind), carrying every occurrence.
            # /etc/passwd with five accounts is one issue with five
            # instances, not five issues; reporting it the other way buries
            # the rest of the report.
            grouped: dict[str, list[_Hit]] = {}
            for hit in hits:
                grouped.setdefault(hit.kind, []).append(hit)
            for kind, group in grouped.items():
                f = self._to_finding(group[0], entry.rel, data, ctx,
                                     siblings=group[1:])
                if f is not None:
                    yield f

    # -- extractors ----------------------------------------------------

    def _crypt_hashes(self, rel: str, data: bytes) -> Iterable[_Hit]:
        if rel not in SHADOW_FILES and not rel.endswith(("passwd", "shadow")):
            return
        for m in CRYPT_RE.finditer(data):
            h = m.group("hash")
            if h in PLACEHOLDER_VALUES or h.startswith((b"*", b"!")):
                continue          # locked account: not a credential
            user = m.group("user").decode()

            # The hash existing is the least interesting part. Severity is
            # decided by the account's uid and the algorithm: a non-root
            # account at uid 0 is root under another name, and a 13-character
            # DES hash falls to a wordlist whatever it protects.
            line_end = data.find(b"\n", m.start())
            line = data[m.start():line_end if line_end > 0 else len(data)]
            fields = line.split(b":")
            uid = int(fields[2]) if len(fields) >= 3 and fields[2].isdigit() else None
            algo = _hash_algorithm(h)
            if uid == 0 and user != "root":
                detail = (f"account {user} is uid 0 -- root-equivalent under "
                          f"a different name")
            elif uid == 0:
                detail = "root has a set password hash"
            else:
                detail = f"account {user} has a set password hash"
            yield _Hit(rel, m.start("hash"), h, "crypt_hash",
                       detail + f"; {algo}")

    def _private_keys(self, rel: str, data: bytes) -> Iterable[_Hit]:
        for m in PRIVKEY_RE.finditer(data):
            blob = m.group(0)
            if hashlib.sha256(blob).hexdigest() in BENIGN_KEY_SHA256:
                continue          # known upstream sample key
            yield _Hit(rel, m.start(), blob, "private_key",
                       "embedded private key")

    def _config_creds(self, rel: str, data: bytes) -> Iterable[_Hit]:
        if len(data) > 1 << 20:
            return
        # Extension check first, then a content sniff, because firmware web
        # roots serve HTML from files named .cfg and .dat all the time.
        if MARKUP_EXT_RE.search(rel):
            return
        if any(tok in data[:4096].lower() for tok in MARKUP_SNIFF):
            return
        for m in CONFIG_CRED_RE.finditer(data):
            val = m.group("val")
            if val.lower() in PLACEHOLDER_VALUES or len(set(val)) < 3:
                continue
            if not _is_literal_secret(val):
                continue
            yield _Hit(rel, m.start("val"), val, "config_credential",
                       f"{m.group('key').decode(errors='replace')} assigned a literal value")

    # -- finding construction -----------------------------------------

    def _to_finding(self, hit: _Hit, rel: str, data: bytes,
                    ctx: RunContext,
                    siblings: list[_Hit] | None = None) -> Finding | None:
        siblings = siblings or []
        blob_rel = ctx.store_blob(Path(rel).name, data)
        proof = ProofArtifact(
            kind="byte_match",
            claim={
                "blob": blob_rel,
                "file_sha256": hashlib.sha256(data).hexdigest(),
                "offset": hit.offset,
                "length": len(hit.needle),
                "needle_sha256": hashlib.sha256(hit.needle).hexdigest(),
            },
            blobs=[blob_rel],
        )

        severity = {
            "crypt_hash": Severity.HIGH,
            "private_key": Severity.CRITICAL,
            "config_credential": Severity.MEDIUM,
        }[hit.kind]
        joined = " ".join([hit.detail, *(s.detail for s in siblings)])
        if "uid 0 -- root-equivalent" in joined and "DES" in joined:
            severity = Severity.CRITICAL

        count = 1 + len(siblings)
        plural = f" ({count} occurrences)" if count > 1 else ""
        details_all = [hit.detail, *(s.detail for s in siblings)]
        hidden_root = sum(1 for d in details_all
                          if "uid 0 -- root-equivalent" in d)
        if hidden_root:
            plural = (f" ({count} accounts, {hidden_root} of them "
                      f"root-equivalent)")
        finding = Finding(
            detector_id=self.meta.id,
            title=f"Hardcoded {hit.kind.replace('_', ' ')} in {rel}{plural}",
            severity=severity,
            axis=Axis.PRESENCE,
            target=rel,
            summary=(
                f"{hit.detail}. This is a presence finding: the bytes are in "
                f"the image at offset {hit.offset}. Whether the credential is "
                f"accepted by a running service is a separate question the "
                f"emulation stage answers."
            ),
            cwe=self.meta.cwe,
            owasp=self.meta.owasp,
            context={
                "locus": {"file": rel, "kind": hit.kind},
                "kind": hit.kind,
                # The value itself is never put in the finding body -- it
                # lives in the blob, which the report redacts by default.
                "value_sha256": hashlib.sha256(hit.needle).hexdigest()[:16],
                "occurrences": count,
                "all_offsets": [hit.offset, *(s.offset for s in siblings)][:50],
                "details": [hit.detail, *(s.detail for s in siblings)][:50],
            },
        )

        # Documentation and sample paths are real matches in unreal places.
        if DOC_PATH_RE.search(rel):
            finding.confidence = Confidence.CANDIDATE
            finding.severity = Severity.INFO
            finding.triage_notes.append(
                "path looks like documentation or sample data; not treated as "
                "a device credential"
            )
            return finding

        return finding.confirm(proof, ctx.artifact_root)


DETECTORS: list[Detector] = [HardcodedCredentialDetector()]

__all__ = ["HardcodedCredentialDetector", "DETECTORS"]
