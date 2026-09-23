"""
sentinel.firmware.analyzers.services
====================================

Works out what the device actually runs, and on which ports.

This stage exists mostly to make the emulation stage useful. Booting a
firmware image blind and port-scanning it wastes minutes and misses services
that need a config nudge to start. Reading the init scripts first tells the
emulator what to expect, what to wait for, and what a failed boot looks like.

It also produces a small number of genuine findings in its own right --
telnetd started unconditionally, a web server running as root, a debug shell
on a serial console -- all PRESENCE claims backed by the config line that
proves them.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

from ...core.contracts import (
    Axis, Confidence, DetectorMeta, Finding, ProofArtifact, RunContext, Severity,
)
from ..models import RootFS, Service

# Vendors do not agree on where init lives. Tenda and several other MIPS
# SDKs ship a read-only /etc_ro that /etc symlinks into, plus a top-level
# /init script; an analyzer that only knows /etc/init.d reports zero services
# on those images and the run looks clean when it is blind.
INIT_DIRS = ["etc/init.d", "etc/rc.d", "etc/rcS.d", "etc/rc.local",
             "etc/inittab", "etc/init", "etc/config", "etc/xinetd.d",
             "etc_ro", "etc_ro/init.d", "etc_ro/inittab", "etc_ro/rc.d",
             "usr/etc", "usr/etc/init.d", "init", "linuxrc",
             "lib/systemd/system", "etc/systemd/system"]

SERVICE_BINARIES = {
    "telnetd": (23, Severity.HIGH, "cleartext remote administration"),
    "utelnetd": (23, Severity.HIGH, "cleartext remote administration"),
    "dropbear": (22, Severity.INFO, "ssh"),
    "sshd": (22, Severity.INFO, "ssh"),
    "ftpd": (21, Severity.MEDIUM, "cleartext file transfer"),
    "vsftpd": (21, Severity.MEDIUM, "cleartext file transfer"),
    "tftpd": (69, Severity.MEDIUM, "unauthenticated file transfer"),
    "lighttpd": (80, Severity.INFO, "web server"),
    "uhttpd": (80, Severity.INFO, "web server"),
    "boa": (80, Severity.INFO, "web server"),
    "goahead": (80, Severity.INFO, "web server"),
    "mini_httpd": (80, Severity.INFO, "web server"),
    "httpd": (80, Severity.INFO, "web server"),
    "bmcweb": (443, Severity.INFO, "redfish/bmc web service"),
    "snmpd": (161, Severity.LOW, "snmp"),
    "upnpd": (1900, Severity.MEDIUM, "upnp"),
    "miniupnpd": (1900, Severity.MEDIUM, "upnp"),
}

def _enabled_services(rootfs) -> set[str] | None:
    """
    Names enabled via runlevel symlinks, or None when the image uses no
    such scheme.

    OpenWrt and sysvinit both ship init scripts for software that is
    installed but switched off, and enable them with an S-prefixed symlink
    in /etc/rc.d (procd) or /etc/rc?.d (sysvinit). Reading /etc/init.d alone
    reports miniupnpd and upnpd as autostarting on an image where neither
    runs -- a false positive that inflates the attack surface of exactly the
    services an operator cares about.
    """
    roots = [rootfs.root / "etc" / "rc.d"]
    roots += [rootfs.root / "etc" / f"rc{n}.d" for n in range(7)]
    found, any_dir = set(), False
    for d in roots:
        if not d.is_dir():
            continue
        any_dir = True
        for entry in d.iterdir():
            n = entry.name
            # S = start, K = stop. An enabled service usually has both (start
            # order and shutdown order); a disabled one has only K. Counting
            # K as enablement made every installed-but-off service look like
            # it autostarts, which is the exact false positive this function
            # exists to remove.
            if n[:1] == "S":
                found.add(n.lstrip("S0123456789"))
    return found if any_dir else None


def _is_text_config(raw: bytes) -> bool:
    """
    Reject anything that is not a plain-text script or config.

    The specific trap: /init and /sbin/init are symlinks to busybox on most
    embedded images, and busybox embeds a table of every applet name it was
    compiled with. Treating that as init configuration reports telnetd, ftpd,
    httpd and friends as autostarting on every busybox image in existence.
    """
    if raw[:4] == b"\x7fELF" or raw[:2] == b"#!" and b"\x00" in raw[:512]:
        return raw[:4] != b"\x7fELF" and b"\x00" not in raw[:512]
    head = raw[:4096]
    if b"\x00" in head:
        return False
    nonprint = sum(1 for b in head if b < 9 or (13 < b < 32) or b > 126)
    return nonprint <= len(head) * 0.05


# systemd directives whose paths are never the service executable. Several
# are sandboxing options, so mistaking them for the binary reports a
# hardening measure as the thing being hardened.
_PATH_DIRECTIVES = (
    "temporaryfilesystem", "bindpaths", "bindreadonlypaths", "readwritepaths",
    "readonlypaths", "inaccessiblepaths", "runtimedirectory", "statedirectory",
    "cachedirectory", "logsdirectory", "configurationdirectory",
    "workingdirectory", "rootdirectory", "rootimage", "environmentfile",
    "pidfile", "conditionpathexists", "requiresmountsfor", "what", "where",
)


PORT_RE = re.compile(r"(?:^|[\s\"'=:])(?:-p|--port|port|listen)\s*[= ]\s*(\d{1,5})\b", re.I)
RUNAS_RE = re.compile(
    r"(?:^|[\s;&|])(?:-u|--user|user)\s*[= ]\s*[\"']?([a-z_][a-z0-9_-]{0,31})", re.I)


class ServiceAnalyzer:
    meta = DetectorMeta(
        id="fw.services.exposed",
        name="Network services started by firmware init",
        severity=Severity.MEDIUM,
        axis=Axis.PRESENCE,
        lane="firmware",
        cwe="CWE-1188",
        proof_kinds=["byte_match"],
        can_confirm=True,
        tags=["services", "init", "attack-surface"],
    )

    def applicable(self, subject: RootFS) -> bool:
        return isinstance(subject, RootFS)

    # ------------------------------------------------------------------

    def discover(self, rootfs: RootFS) -> list[Service]:
        services: dict[str, Service] = {}
        enabled = _enabled_services(rootfs)
        for rel in INIT_DIRS:
            base = rootfs.root / rel
            if not base.exists():
                continue
            files = [base] if base.is_file() else [
                p for p in base.rglob("*")
                if p.is_file() and p.stat().st_size < (1 << 20)
            ]
            for f in files:
                try:
                    raw = f.read_bytes()
                except OSError:
                    continue
                if not _is_text_config(raw):
                    continue
                self._scan_text(raw.decode("utf-8", "replace"), f, rootfs,
                                services)

        # Where the image expresses enablement, respect it. Where it does not
        # (no rc.d at all), every script is assumed to run, as before.
        if enabled is not None:
            for name, svc in services.items():
                if not any(name in e or e in name for e in enabled):
                    svc.autostart = False
                    svc.evidence.append(
                        "no rc.d symlink: installed but not enabled")
        return list(services.values())

    def _scan_text(self, text: str, path: Path, rootfs: RootFS,
                   out: dict[str, Service]) -> None:
        rel = str(path.relative_to(rootfs.root))
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for name, (default_port, _sev, _why) in SERVICE_BINARIES.items():
                if not re.search(rf"\b{re.escape(name)}\b", stripped):
                    continue
                svc = out.setdefault(name, Service(name=name, binary=None))
                svc.autostart = True
                svc.config_paths.append(rel)
                svc.evidence.append(f"{rel}: {stripped[:160]}")
                pm = PORT_RE.search(stripped)
                svc.port = int(pm.group(1)) if pm and int(pm.group(1)) < 65536 \
                    else (svc.port or default_port)
                um = RUNAS_RE.search(stripped)
                if um:
                    svc.runs_as = um.group(1)
                lower = stripped.lower()
                if lower.startswith(("execstart", "execstartpre")):
                    em = re.search(r"=\s*[-@+!]*(/\S+)", stripped)
                    if em:
                        svc.binary = em.group(1)
                elif not any(lower.startswith(d) for d in _PATH_DIRECTIVES):
                    bm = re.search(rf"(/\S*{re.escape(name)})\b", stripped)
                    if bm and not svc.binary:
                        svc.binary = bm.group(1)

    # ------------------------------------------------------------------

    def orphan_binaries(self, services: list[Service],
                        rootfs: RootFS) -> list[str]:
        """
        Service binaries present in the image that no init config mentions.

        This is the honest answer to a hard limit. Tenda and many other
        vendors start their daemons from compiled code -- /init is busybox,
        rcS hands off to a proprietary supervisor, and nothing in any text
        file names httpd. Static config parsing cannot follow that, and
        reporting "0 services" silently implies the device has no network
        surface, which is the most dangerous output this analyzer can give.

        So: name the binaries we can see, say we could not find what starts
        them, and point at the stage that can answer it.
        """
        named = {s.name for s in services}
        found: list[str] = []
        for entry in rootfs.walk(max_size=32 << 20):
            base = entry.rel.rsplit("/", 1)[-1]
            if base in SERVICE_BINARIES and base not in named \
                    and entry.executable and not entry.is_symlink:
                found.append(entry.rel)
        return sorted(set(found))

    def coverage_finding(self, orphans: list[str], services: list[Service],
                         rootfs: RootFS, ctx: RunContext) -> Finding | None:
        if not orphans:
            return None
        return Finding(
            detector_id="fw.services.unexplained",
            title=(f"{len(orphans)} service binaries present that no init "
                   f"configuration starts"),
            severity=Severity.INFO,
            axis=Axis.PRESENCE,
            target=str(rootfs.root.name),
            summary=(
                "These daemons are in the image but nothing in any readable "
                "init script, inittab or config references them, so this "
                "analyzer cannot say whether they run, on which ports, or as "
                "which user. On images where /init is busybox and startup is "
                "driven from compiled code, that is expected rather than a "
                "parsing failure. Treat the attack surface as unknown, not "
                "absent, and resolve it by emulating the image or by "
                "reversing whatever rcS hands control to."
            ),
            confidence=Confidence.PROBABLE,
            context={
                "locus": {"scope": "image", "check": "service_coverage"},
                "unexplained_binaries": orphans[:40],
                "explained_services": [s.name for s in services],
            },
            triage_notes=["coverage gap, not a vulnerability; it marks where "
                          "static analysis stops"],
        )

    def findings(self, services: list[Service], rootfs: RootFS,
                 ctx: RunContext) -> Iterable[Finding]:
        for svc in services:
            if not svc.autostart:
                continue          # installed, not enabled
            _, sev, why = SERVICE_BINARIES.get(svc.name, (None, Severity.INFO, ""))
            if sev in (Severity.INFO,) and svc.runs_as not in (None, "root"):
                continue

            root_run = svc.runs_as in (None, "root")
            if sev == Severity.INFO and not root_run:
                continue

            title = f"{svc.name} starts automatically"
            if root_run and svc.web:
                title = f"{svc.name} web service starts automatically as root"
                sev = Severity.MEDIUM if sev.rank < 2 else sev

            f = Finding(
                detector_id=self.meta.id,
                title=title,
                severity=sev,
                axis=Axis.PRESENCE,
                target=svc.binary or svc.name,
                summary=(
                    f"Init configuration starts {svc.name}"
                    + (f" on port {svc.port}" if svc.port else "")
                    + (f" as {svc.runs_as or 'root'}" if root_run else "")
                    + (f" ({why})" if why else "")
                    + ". The configuration line proving this is stored as "
                      "evidence. Whether the service is reachable on a "
                      "deployed device depends on firewall rules not present "
                      "in the image."
                ),
                confidence=Confidence.PROBABLE,
                cwe=self.meta.cwe,
                context={
                    "locus": {"service": svc.name},
                    "port": svc.port, "runs_as": svc.runs_as or "root",
                    "config_paths": svc.config_paths,
                    "evidence_lines": svc.evidence[:5],
                },
            )

            src = rootfs.root / (svc.config_paths[0] if svc.config_paths else "")
            if src.is_file():
                data = src.read_bytes()
                rel = ctx.store_blob(Path(svc.config_paths[0]).name, data)
                needle = svc.name.encode()
                off = data.find(needle)
                if off >= 0:
                    proof = ProofArtifact(
                        kind="byte_match",
                        claim={"blob": rel,
                               "file_sha256": hashlib.sha256(data).hexdigest(),
                               "offset": off, "length": len(needle),
                               "needle_sha256": hashlib.sha256(needle).hexdigest()},
                        blobs=[rel],
                    )
                    try:
                        f.confirm(proof, ctx.artifact_root)
                    except Exception:
                        pass
            yield f


__all__ = ["ServiceAnalyzer", "SERVICE_BINARIES"]
