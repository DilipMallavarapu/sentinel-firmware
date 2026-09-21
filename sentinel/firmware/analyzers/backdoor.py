"""
sentinel.firmware.analyzers.backdoor
====================================

Detectors derived from the published firmware corpus rather than from
guesswork about what might be wrong.

Primary source is Costin et al., "A Large-Scale Analysis of the Security of
Embedded Firmwares" (USENIX Security 2014) — 32,356 images, 1.7M files, 38
new CVEs. What that study actually found, in the order it found it:

  * `authorized_keys` files shipped inside images. An SSH key in firmware is
    remote root for whoever holds the private half, on every device of that
    model. They list it first among backdoor indicators.
  * 109 private RSA keys across 428 images, and 41 cases where the private
    key shipped alongside its own self-signed certificate. Those certs were
    then found on ~35,000 internet-reachable devices. Same key on every unit
    means passive TLS decryption for the whole fleet.
  * A plain keyword search for backdoor-related strings: 1198 matches across
    326 images. Unglamorous and effective. The D-Link case was findable by
    grepping the vendor's own GPL release.
  * Compilation banners naming the build user: 24% of 450 unique banners were
    built as root, and 10 of 267 extracted hostnames resolved to public IPs.
    Release hygiene, and occasionally a live host.

Modern CVE data adds one dominant shape the 2014 study predates: command
injection in CGI binaries, where a request parameter reaches system() or
popen(). CVE-2023-1389 (TP-Link `country` → popen), CVE-2024-48456 (Netis
`password` → RunSystemCmd), CVE-2025-7850, and the GeoVision and Atlona
cases are all the same bug written by different people.

That last one is a *triage* signal here, not a finding. A CGI binary that
imports system() is not vulnerable; it is worth opening first. The detector
says exactly that and nothing stronger, because the alternative — calling
every popen() a command injection — is how a scanner becomes unreadable.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)
from ..models import RootFS

# --------------------------------------------------------------------------
# 1. authorized_keys
# --------------------------------------------------------------------------

AUTHORIZED_KEYS_RE = re.compile(
    rb"(?:^|\n)\s*(?:ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp\d+)\s+"
    rb"(?P<key>[A-Za-z0-9+/]{60,}={0,3})(?:\s+(?P<comment>\S+))?")


class AuthorizedKeysDetector:
    """
    An SSH public key shipped in firmware.

    Costin et al. list this first among backdoor indicators, and it is the
    cleanest one to prove: the key is either in the image or it is not, and
    the bytes settle it. What the finding cannot settle is intent — a
    deliberate implant and a developer key left behind by accident produce
    identical files. The summary says so rather than guessing.
    """
    meta = DetectorMeta(
        id="fw.backdoor.authorized_keys",
        name="SSH authorized_keys shipped in the image",
        severity=Severity.CRITICAL,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-798",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["backdoor", "ssh", "credentials"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        for entry in subject.walk(max_size=1 << 20):
            name = entry.rel.rsplit("/", 1)[-1]
            if name not in ("authorized_keys", "authorized_keys2",
                            "authorized_keys.dropbear") \
                    and "dropbear" not in entry.rel:
                continue
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            keys = list(AUTHORIZED_KEYS_RE.finditer(data))
            if not keys:
                continue

            comments = [m.group("comment").decode("utf-8", "replace")
                        for m in keys if m.group("comment")]
            blob = ctx.store_blob(name, data)
            m0 = keys[0]
            proof = ProofArtifact(
                kind="byte_match",
                claim={"blob": blob,
                       "file_sha256": hashlib.sha256(data).hexdigest(),
                       "offset": m0.start("key"),
                       "length": len(m0.group("key")),
                       "needle_sha256": hashlib.sha256(m0.group("key")).hexdigest()},
                blobs=[blob],
            )
            f = Finding(
                detector_id=self.meta.id,
                title=(f"{len(keys)} SSH public key(s) shipped in {entry.rel}"),
                severity=Severity.CRITICAL,
                axis=Axis.PRESENCE,
                target=entry.rel,
                summary=(
                    f"This file authorises SSH login for whoever holds the "
                    f"matching private key, on every device running this "
                    f"image. Whether it is a deliberate implant or a "
                    f"developer key left in a release build cannot be "
                    f"determined from the bytes — both look exactly like "
                    f"this. Check the key comments against the vendor and "
                    f"ask them directly."
                ),
                cwe=self.meta.cwe,
                context={
                    "locus": {"file": entry.rel},
                    "key_count": len(keys),
                    "key_comments": comments[:10],
                    "key_fingerprints": [
                        hashlib.sha256(m.group("key")).hexdigest()[:16]
                        for m in keys[:10]],
                },
            )
            try:
                yield f.confirm(proof, ctx.artifact_root)
            except Exception:
                f.confidence = Confidence.PROBABLE
                yield f


# --------------------------------------------------------------------------
# 2. Private key shipped with its own certificate
# --------------------------------------------------------------------------

PRIVKEY_BLOCK = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"
    rb"[A-Za-z0-9+/=\s]{100,}-----END (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----")
CERT_BLOCK = re.compile(
    rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]{100,}-----END CERTIFICATE-----")


class ShippedTlsKeypairDetector:
    """
    A TLS private key and a certificate in the same image.

    Costin et al. found 41 such pairs and then located the same certificates
    on roughly 35,000 internet-reachable devices. The consequence is not
    subtle: if the device does not regenerate on first boot, anyone who
    downloads the firmware can decrypt HTTPS to every unit of that model,
    passively, forever.

    Regeneration on first boot is the one thing that makes this benign, and
    it cannot be determined from the filesystem — it is an init-time
    behaviour. Reported as PROBABLE with that question stated, rather than
    asserted either way.
    """
    meta = DetectorMeta(
        id="fw.backdoor.shipped_tls_keypair",
        name="TLS private key and certificate shipped together",
        severity=Severity.HIGH,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-321",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["tls", "keys", "fleet"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        keys: list[tuple[str, bytes, int]] = []
        certs: list[tuple[str, bytes, int]] = []

        for entry in subject.walk(max_size=1 << 20):
            if not re.search(r"\.(pem|crt|cer|key|p12|conf|cnf)$|/ssl/|/certs?/",
                             entry.rel, re.I):
                continue
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            for m in PRIVKEY_BLOCK.finditer(data):
                keys.append((entry.rel, data, m.start()))
            for m in CERT_BLOCK.finditer(data):
                certs.append((entry.rel, data, m.start()))

        if not (keys and certs):
            return

        rel, data, off = keys[0]
        blob = ctx.store_blob(Path(rel).name, data)
        needle = data[off:off + 64]
        proof = ProofArtifact(
            kind="byte_match",
            claim={"blob": blob,
                   "file_sha256": hashlib.sha256(data).hexdigest(),
                   "offset": off, "length": 64,
                   "needle_sha256": hashlib.sha256(needle).hexdigest()},
            blobs=[blob],
        )
        f = Finding(
            detector_id=self.meta.id,
            title=(f"TLS private key and certificate both shipped "
                   f"({len(keys)} key(s), {len(certs)} cert(s))"),
            severity=Severity.HIGH,
            axis=Axis.PRESENCE,
            target=rel,
            summary=(
                "The image contains both a private key and a certificate. If "
                "the device does not regenerate these on first boot, every "
                "unit of this model shares them, and anyone with the firmware "
                "can decrypt its HTTPS traffic passively. Whether "
                "regeneration happens is an init-time behaviour and is not "
                "decidable from the filesystem — check the startup scripts, "
                "or boot it and compare the served certificate against this "
                "one."
            ),
            confidence=Confidence.PROBABLE,
            cwe=self.meta.cwe,
            context={
                "locus": {"file": rel},
                "key_files": sorted({k[0] for k in keys})[:10],
                "cert_files": sorted({c[0] for c in certs})[:10],
                "verify_next": "boot the image and diff the served cert",
            },
        )
        try:
            f.confirm(proof, ctx.artifact_root)
            # Presence of the pair is proven; fleet-wide impact is not.
            f.confidence = Confidence.CONFIRMED
        except Exception:
            pass
        yield f


# --------------------------------------------------------------------------
# 3. Build banners
# --------------------------------------------------------------------------

BANNER_RE = re.compile(
    rb"(?:Linux version|BusyBox v|gcc version)[^\n\x00]{0,200}?"
    rb"\((?P<user>[a-z_][a-z0-9_.-]{0,31})@(?P<host>[A-Za-z0-9_.-]{2,64})\)")


class BuildBannerDetector:
    """
    Who built this image, on what host.

    Costin et al. found 24% of build banners naming root as the build user,
    and ten of 267 extracted hostnames resolving to public IPs — one of which
    accepted SSH. This is release hygiene rather than a vulnerability in the
    device, which is why it is INFO, but the hostnames are occasionally a
    live target and the toolchain version dates the image better than any
    version string the vendor prints.
    """
    meta = DetectorMeta(
        id="fw.build.banner",
        name="Build environment leaked in compilation banners",
        severity=Severity.INFO,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-200",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["hygiene", "recon"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        seen: dict[tuple[str, str], str] = {}
        first: tuple[str, bytes, int, bytes] | None = None

        for entry in subject.walk(max_size=16 << 20):
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            for m in BANNER_RE.finditer(data):
                user = m.group("user").decode("utf-8", "replace")
                host = m.group("host").decode("utf-8", "replace")
                seen.setdefault((user, host), entry.rel)
                if first is None:
                    first = (entry.rel, data, m.start(), m.group(0))

        if not seen or first is None:
            return

        root_built = [f"{u}@{h}" for (u, h) in seen if u == "root"]
        rel, data, off, needle = first
        blob = ctx.store_blob(Path(rel).name, data)
        proof = ProofArtifact(
            kind="byte_match",
            claim={"blob": blob,
                   "file_sha256": hashlib.sha256(data).hexdigest(),
                   "offset": off, "length": len(needle),
                   "needle_sha256": hashlib.sha256(needle).hexdigest()},
            blobs=[blob],
        )
        f = Finding(
            detector_id=self.meta.id,
            title=(f"{len(seen)} build banner(s) leak the build environment"
                   + (f"; {len(root_built)} built as root" if root_built else "")),
            severity=Severity.LOW if root_built else Severity.INFO,
            axis=Axis.PRESENCE,
            target=rel,
            summary=(
                "Compilation banners name the user and host that produced "
                "this image. Building as root is a toolchain smell rather "
                "than a device vulnerability, but the hostnames are worth "
                "resolving — published work found build hosts reachable on "
                "the public internet, one accepting SSH."
            ),
            cwe=self.meta.cwe,
            context={
                "locus": {"scope": "image", "check": "build_banner"},
                "builders": [f"{u}@{h}" for (u, h) in sorted(seen)][:20],
                "built_as_root": root_built[:10],
            },
        )
        try:
            yield f.confirm(proof, ctx.artifact_root)
        except Exception:
            f.confidence = Confidence.PROBABLE
            yield f


# --------------------------------------------------------------------------
# 4. Command-injection sink triage
# --------------------------------------------------------------------------

# The modern CVE corpus is dominated by one shape: a request parameter
# reaching system() or popen() inside a CGI binary. These strings indicate a
# binary handles request parameters at all.
CGI_PARAM_MARKERS = (b"QUERY_STRING", b"REQUEST_METHOD", b"CONTENT_LENGTH",
                     b"HTTP_COOKIE", b"PATH_INFO")
SHELL_SINKS = (b"system", b"popen", b"execl", b"execlp", b"execvp", b"/bin/sh")
FORMAT_MARKERS = (b"%s", b"sprintf", b"snprintf", b"vsnprintf")


class InjectionSinkTriage:
    """
    Which binary to open in a disassembler first.

    Deliberately not a vulnerability finding. A CGI binary that calls
    system() is not a bug — it is the shape every command-injection CVE in
    this class happens to have, which makes it a ranking signal and nothing
    more. Reported as INFO on the presence axis with an explicit statement
    that no vulnerability is being claimed.

    The value is ordering. A router image has thirty to eighty CGI handlers;
    this says which five combine request-parameter handling, a shell sink and
    format-string construction in the same binary. That is where CVE-2023-1389
    and CVE-2024-48456 both lived.
    """
    meta = DetectorMeta(
        id="fw.triage.injection_sinks",
        name="Request handlers that reach a shell",
        severity=Severity.INFO,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-78",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["triage", "command-injection", "review-order"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    def run(self, subject: RootFS, ctx: RunContext) -> Iterable[Finding]:
        ranked: list[tuple[int, str, list[str], bytes, int]] = []

        for entry in subject.walk(max_size=16 << 20):
            try:
                data = entry.abspath.read_bytes()
            except OSError:
                continue
            if data[:4] != b"\x7fELF":
                continue

            params = [m.decode() for m in CGI_PARAM_MARKERS if m in data]
            if not params:
                continue
            sinks = [m.decode() for m in SHELL_SINKS if m in data]
            if not sinks:
                continue
            fmts = [m.decode() for m in FORMAT_MARKERS if m in data]

            score = len(params) * 2 + len(sinks) * 3 + len(fmts)
            if any(seg in entry.rel for seg in ("cgi-bin/", "www/", "web/")):
                score += 6
            ranked.append((score, entry.rel, params + sinks + fmts,
                           data, data.find(sinks[0].encode())))

        if not ranked:
            return
        ranked.sort(key=lambda t: -t[0])

        for score, rel, markers, data, off in ranked[:10]:
            blob = ctx.store_blob(rel.replace("/", "_"), data[:1 << 20])
            needle = data[off:off + 16]
            proof = ProofArtifact(
                kind="byte_match",
                claim={"blob": blob,
                       "file_sha256": hashlib.sha256(data[:1 << 20]).hexdigest(),
                       "offset": off, "length": 16,
                       "needle_sha256": hashlib.sha256(needle).hexdigest()},
                blobs=[blob],
            )
            f = Finding(
                detector_id=self.meta.id,
                title=f"Review priority {score}: {rel} handles requests and reaches a shell",
                severity=Severity.INFO,
                axis=Axis.PRESENCE,
                target=rel,
                summary=(
                    f"This binary references CGI request variables and a "
                    f"shell execution function in the same image. That is the "
                    f"shape of every command-injection CVE in this class "
                    f"(TP-Link CVE-2023-1389, Netis CVE-2024-48456 and many "
                    f"others), so it is where manual review pays off first. "
                    f"No vulnerability is claimed: reaching a shell is normal "
                    f"for a device handler, and only reading the code shows "
                    f"whether the parameter is sanitised."
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                context={
                    "locus": {"file": rel},
                    "review_score": score,
                    "markers": markers[:12],
                    "next_step": "disassemble and trace the parameter to the sink",
                },
                triage_notes=["ranking signal, not a finding; do not report "
                              "to a vendor as a vulnerability"],
            )
            try:
                f.confirm(proof, ctx.artifact_root)
                f.confidence = Confidence.PROBABLE   # never confirmed: it is a hint
            except Exception:
                pass
            yield f


DETECTORS = [AuthorizedKeysDetector(), ShippedTlsKeypairDetector(),
             BuildBannerDetector(), InjectionSinkTriage()]

__all__ = ["AuthorizedKeysDetector", "ShippedTlsKeypairDetector",
           "BuildBannerDetector", "InjectionSinkTriage", "DETECTORS"]
