"""
sentinel.core.verifiers
=======================

Concrete offline re-checks for each proof kind.

Rules every verifier here obeys:
  * No network. Ever. A verifier that needs the target is not a verifier.
  * No model calls. Determinism is the whole point.
  * Operates only on bytes stored under the run's artifact root.
  * Returns False rather than raising on missing/garbled evidence -- a proof
    we cannot re-check is a proof that fails.

If you add a proof kind, you add its verifier here in the same commit. The
registry will refuse to load a detector whose declared proof kinds have no
verifier, so this file is the gate that keeps CONFIRMED honest.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from .contracts import ProofArtifact, verifier


def _read(root: Path, rel: str) -> bytes | None:
    p = (root / rel).resolve()
    try:
        # Containment check: a proof must never point outside the run dir.
        p.relative_to(root.resolve())
    except ValueError:
        return None
    return p.read_bytes() if p.is_file() else None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------

@verifier("byte_match")
def verify_byte_match(proof: ProofArtifact, root: Path) -> bool:
    """
    The strongest proof we have, and the backbone of firmware findings.

    claim = {
        "blob": "blobs/ab12_shadow",   # the captured file
        "file_sha256": "...",          # what it hashed to at capture time
        "offset": 420,
        "needle_sha256": "...",        # sha of the exact matched bytes
        "length": 57,
    }

    Passes only if the stored file still hashes to the recorded digest and the
    bytes at the recorded offset still hash to the recorded needle digest.
    There is no interpretation here, which is exactly why it cannot be wrong.
    """
    c = proof.claim
    data = _read(root, c.get("blob", ""))
    if data is None or _sha(data) != c.get("file_sha256"):
        return False
    off, ln = int(c.get("offset", -1)), int(c.get("length", 0))
    if off < 0 or ln <= 0 or off + ln > len(data):
        return False
    return _sha(data[off:off + ln]) == c.get("needle_sha256")


@verifier("symbol_presence")
def verify_symbol_presence(proof: ProofArtifact, root: Path) -> bool:
    """
    Re-derives a symbol-derived mitigation verdict (canary / fortify) from the
    exact bytes that were searched, not from the ELF header.

    This is the proof that byte_match(offset=0, length=64) could never be: the
    old header proof re-confirmed the file was unchanged and asserted nothing
    about whether a canary symbol was present. Here the stored blob *is* the
    string table region (for present/absent) or the ELF header + program
    header table (for unknown), and the verdict is reproduced from it.

    claim, result == "present":
        {"blob", "region_sha256", "needle": "stack_chk",
         "match_off_in_region": 325}   # needle bytes sit at this offset

    claim, result == "absent":
        {"blob", "region_sha256", "needle": "stack_chk"}
        # blob is the whole searched string table; the token appears nowhere

    claim, result == "unknown":
        {"blob", "region_sha256", "reason": "..."}
        # blob is header+phdrs; re-derives that no symbol source exists at all
    """
    c = proof.claim
    data = _read(root, c.get("blob", ""))
    if data is None or _sha(data) != c.get("region_sha256"):
        return False

    result = c.get("result")
    if result == "present":
        needle = str(c.get("needle", "")).encode()
        off = int(c.get("match_off_in_region", -1))
        if not needle or off < 0 or off + len(needle) > len(data):
            return False
        return data[off:off + len(needle)] == needle
    if result == "absent":
        needle = str(c.get("needle", "")).encode()
        # The blob is the entire region that was searched, so "not present in
        # this region" is a complete, re-checkable statement of absence.
        return bool(needle) and needle not in data
    if result == "unknown":
        # The claim is that no symbol source exists to read: no section headers
        # and no PT_DYNAMIC segment. Both are re-derived from the raw header.
        return _elf_has_no_symbol_source(data)
    return False


def _elf_has_no_symbol_source(data: bytes) -> bool:
    """
    Re-derives the worker's canary=unknown condition from the whole ELF: there
    is *no* symbol-bearing section (SHT_SYMTAB / SHT_DYNSYM) **and** no dynamic
    string table reachable from PT_DYNAMIC. This is a second, independent
    implementation of scanSymbols' fallback logic -- if either symbol source
    can be found, the verdict was not "unknown" and this returns False.

    A note on why the ELF header alone is not enough: `strip -s` on a static
    binary removes .symtab while keeping the section header table, so an
    e_shnum==0 test would miss it. Only walking the sections for a symbol type,
    and the segments for a usable strtab, reproduces what the worker did.
    """
    import struct
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return False
    is64 = data[4] == 2
    end = "<" if data[5] == 1 else ">"
    SHT_SYMTAB, SHT_DYNSYM, PT_DYNAMIC, PT_LOAD = 2, 11, 2, 1
    DT_NULL, DT_STRTAB, DT_STRSZ = 0, 5, 10
    try:
        if is64:
            e_phoff, e_shoff = struct.unpack_from(end + "QQ", data, 0x20)
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 0x36)
            e_shentsize, e_shnum = struct.unpack_from(end + "HH", data, 0x3A)
        else:
            e_phoff = struct.unpack_from(end + "I", data, 0x1C)[0]
            e_shoff = struct.unpack_from(end + "I", data, 0x20)[0]
            e_phentsize, e_phnum = struct.unpack_from(end + "HH", data, 0x2A)
            e_shentsize, e_shnum = struct.unpack_from(end + "HH", data, 0x2E)

        # 1) any symbol-bearing section -> the worker could read symbols.
        for i in range(e_shnum):
            base = e_shoff + i * e_shentsize
            if base + 8 > len(data):
                return False  # section table not fully captured; cannot re-derive
            sh_type = struct.unpack_from(end + "I", data, base + 4)[0]
            if sh_type in (SHT_SYMTAB, SHT_DYNSYM):
                return False

        # 2) a dynamic segment whose DT_STRTAB lands in a loadable segment ->
        #    the worker could read .dynstr. Reproduce that lookup exactly.
        loads = []  # (vaddr, off, filesz)
        dyn = None  # (off, filesz)
        for i in range(e_phnum):
            base = e_phoff + i * e_phentsize
            if base + e_phentsize > len(data):
                return False
            p_type = struct.unpack_from(end + "I", data, base)[0]
            if is64:
                p_off, p_vaddr = struct.unpack_from(end + "QQ", data, base + 8)
                p_filesz = struct.unpack_from(end + "Q", data, base + 32)[0]
            else:
                p_off, p_vaddr, _pp, p_filesz = struct.unpack_from(
                    end + "IIII", data, base + 4)
            if p_type == PT_LOAD:
                loads.append((p_vaddr, p_off, p_filesz))
            elif p_type == PT_DYNAMIC:
                dyn = (p_off, p_filesz)

        if dyn is not None:
            off, size = dyn
            step = 16 if is64 else 8
            strtab_va = strsz = None
            for p in range(off, min(off + size, len(data)) - step + 1, step):
                if is64:
                    tag, val = struct.unpack_from(end + "QQ", data, p)
                else:
                    tag, val = struct.unpack_from(end + "II", data, p)
                if tag == DT_STRTAB:
                    strtab_va = val
                elif tag == DT_STRSZ:
                    strsz = val
                elif tag == DT_NULL:
                    break
            if strtab_va is not None and strsz:
                for vaddr, poff, filesz in loads:
                    if vaddr <= strtab_va and strtab_va + strsz <= vaddr + filesz:
                        return False  # .dynstr is readable: not unknown
    except struct.error:
        return False
    return True


@verifier("pattern_match")
def verify_pattern_match(proof: ProofArtifact, root: Path) -> bool:
    """
    Regex re-application against stored bytes. Weaker than byte_match because
    the pattern is authored by us, so it is only allowed for detectors whose
    pattern has a structural validator attached (a crypt(3) hash shape, a PEM
    header plus a base64 body that decodes, an RSA modulus of legal length).

    claim = {"blob": ..., "file_sha256": ..., "pattern": ...,
             "expect_groups": ["root", "$1$..."], "validator": "crypt_hash"}
    """
    c = proof.claim
    data = _read(root, c.get("blob", ""))
    if data is None or _sha(data) != c.get("file_sha256"):
        return False
    try:
        m = re.search(c["pattern"].encode(), data)
    except re.error:
        return False
    if not m:
        return False
    got = [g.decode("utf-8", "replace") for g in m.groups()]
    if got != list(c.get("expect_groups", got)):
        return False
    val = _VALIDATORS.get(c.get("validator", ""))
    return val(got) if val else True


def _v_crypt_hash(groups: list[str]) -> bool:
    """A real crypt(3) hash, not a comment that looks like one."""
    h = groups[-1]
    return bool(re.fullmatch(r"\$[1256][aby]?\$[^$]{1,64}\$[./A-Za-z0-9]{16,}", h)) \
        or bool(re.fullmatch(r"[./A-Za-z0-9]{13}", h))


def _v_pem_block(groups: list[str]) -> bool:
    import base64
    body = re.sub(r"\s+", "", groups[-1])
    try:
        return len(base64.b64decode(body, validate=True)) >= 64
    except Exception:
        return False


_VALIDATORS = {"crypt_hash": _v_crypt_hash, "pem_block": _v_pem_block}


@verifier("differential")
def verify_differential(proof: ProofArtifact, root: Path) -> bool:
    """
    Control-vs-probe response differential, for injection classes on the web
    lane. Both bodies are stored at detection time.

    The claim must name the divergence *and* assert the control is stable:
    we store two control responses, and if the two controls already differ in
    the same dimension the target is simply noisy and the finding is void.
    That second control is what removes the bulk of blind-SQLi false
    positives.

    claim = {"control_a": ..., "control_b": ..., "probe": ...,
             "dimension": "length" | "status" | "body_sha",
             "min_delta": 32}
    """
    c = proof.claim
    a = _read(root, c.get("control_a", ""))
    b = _read(root, c.get("control_b", ""))
    p = _read(root, c.get("probe", ""))
    if a is None or b is None or p is None:
        return False

    dim = c.get("dimension")
    if dim == "body_sha":
        return _sha(a) == _sha(b) and _sha(p) != _sha(a)
    if dim == "status":
        sa, sb, sp = (json.loads(x or b"{}").get("status") for x in (a, b, p))
        return sa == sb and sp != sa
    if dim == "length":
        delta = abs(len(p) - len(a))
        control_noise = abs(len(b) - len(a))
        return delta >= int(c.get("min_delta", 32)) and control_noise < delta // 4
    return False


@verifier("oob_callback")
def verify_oob_callback(proof: ProofArtifact, root: Path) -> bool:
    """
    Out-of-band interaction. The canary must be high-entropy and bound to a
    single probe, so a recorded hit cannot be attributed to anything else.

    claim = {"canary": "<32 hex>.oob.example", "probe_binding_sha256": ...,
             "log_blob": "blobs/..oob.jsonl"}

    We re-read the interaction log and require exactly one hit for the canary.
    Two hits means something is replaying our probes and the attribution is
    no longer sound.
    """
    c = proof.claim
    canary = c.get("canary", "")
    token = canary.split(".")[0]
    if len(token) < 24:
        return False
    log = _read(root, c.get("log_blob", ""))
    if log is None:
        return False
    hits = [ln for ln in log.decode("utf-8", "replace").splitlines() if token in ln]
    return len(hits) == 1


@verifier("runtime_diff")
def verify_runtime_diff(proof: ProofArtifact, root: Path) -> bool:
    """
    The only way a firmware finding crosses from PRESENCE to REACHABILITY.

    Requires a stored transcript from the emulated device showing that an
    unauthenticated request reached the code path, plus a control transcript
    showing the same request without the triggering input did not.

    claim = {"control_transcript": ..., "probe_transcript": ...,
             "observable": "status" | "marker", "marker": "uid=0(root)"}
    """
    c = proof.claim
    ctrl = _read(root, c.get("control_transcript", ""))
    ctrl_b = _read(root, c.get("control_b_transcript", ""))
    probe = _read(root, c.get("probe_transcript", ""))
    if ctrl is None or probe is None:
        return False

    # Re-check the noise condition, not just the divergence. Two identical
    # requests that already disagree mean the endpoint is non-deterministic
    # and no divergence from it proves anything. Enforcing this here rather
    # than only at detection time is what makes the proof re-checkable.
    if ctrl_b is not None:
        try:
            a, b = json.loads(ctrl), json.loads(ctrl_b)
            if c.get("observable") == "status":
                if a.get("status") != b.get("status"):
                    return False
            elif abs(len(a.get("stdout", "")) - len(b.get("stdout", ""))) >= 48:
                return False
        except (json.JSONDecodeError, ValueError):
            return False

    if c.get("observable") == "marker":
        m = c.get("marker", "").encode()
        return bool(m) and m in probe and m not in ctrl
    try:
        a, p = json.loads(ctrl), json.loads(probe)
    except (json.JSONDecodeError, ValueError):
        return False
    if c.get("observable") == "length":
        return abs(len(p.get("stdout", "")) - len(a.get("stdout", ""))) >= 48
    cs, ps = a.get("status"), p.get("status")
    return cs != ps and ps is not None


@verifier("sbom_pin")
def verify_sbom_pin(proof: ProofArtifact, root: Path) -> bool:
    """
    For CANDIDATE-tier version findings. Proves the *version string* exists,
    never that the CVE applies. Present so version findings still carry
    re-checkable evidence even though they stay at CANDIDATE.
    """
    return verify_byte_match(proof, root)


__all__ = ["verify_byte_match", "verify_pattern_match", "verify_differential",
           "verify_oob_callback", "verify_runtime_diff", "verify_sbom_pin"]
