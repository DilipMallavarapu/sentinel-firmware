"""
sentinel.firmware.models
========================

Domain objects for the firmware lane.

The shape here is deliberately different from the web lane. A web target is a
live thing you interrogate; a firmware image is a frozen artifact you read.
The one place they meet is `EmulatedTarget`, which turns a rootfs back into
something the existing web detectors can point at unchanged -- that is the
whole reason the two lanes share `core.contracts`.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional


@dataclass
class FirmwareImage:
    path: Path
    sha256: str
    size: int
    vendor: Optional[str] = None
    model: Optional[str] = None
    version: Optional[str] = None
    notes: str = ""

    @classmethod
    def from_file(cls, path: str | Path) -> "FirmwareImage":
        p = Path(path)
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return cls(path=p, sha256=h.hexdigest(), size=p.stat().st_size)


@dataclass
class Partition:
    """One extracted region: a squashfs/jffs2/ubifs blob, a kernel, a bootloader."""
    index: int
    offset: int
    size: int
    kind: str                     # "squashfs", "cramfs", "uimage", "unknown"
    extracted_to: Optional[Path] = None
    entropy: float = 0.0          # high + unidentified => encrypted/packed


@dataclass
class FileEntry:
    rel: str                      # path relative to rootfs, no leading slash
    abspath: Path
    size: int
    mode: int
    is_symlink: bool = False
    link_target: Optional[str] = None

    @property
    def setuid(self) -> bool:
        return bool(self.mode & stat.S_ISUID)

    @property
    def world_writable(self) -> bool:
        return bool(self.mode & stat.S_IWOTH)

    @property
    def executable(self) -> bool:
        return bool(self.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


@dataclass
class RootFS:
    """
    An extracted filesystem, with a safe walker.

    Firmware archives are hostile input: symlinks pointing at /etc/passwd on
    the analysis host, paths with .. in them, device nodes, 4GB sparse files.
    Every traversal in the firmware lane goes through `walk()`, which stays
    inside the extraction root and never follows a link out of it.
    """
    root: Path
    arch: Optional[str] = None          # "arm", "mipsel", "aarch64", ...
    endian: Optional[str] = None
    libc: Optional[str] = None          # "uclibc", "musl", "glibc"
    init_system: Optional[str] = None   # "sysvinit", "procd", "systemd", "busybox"

    def walk(self, max_size: int = 64 << 20) -> Iterator[FileEntry]:
        base = self.root.resolve()
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            d = Path(dirpath)
            for name in filenames:
                p = d / name
                try:
                    st = p.lstat()
                except OSError:
                    continue
                if stat.S_ISLNK(st.st_mode):
                    yield FileEntry(
                        rel=str(p.relative_to(base)), abspath=p, size=st.st_size,
                        mode=st.st_mode, is_symlink=True,
                        link_target=os.readlink(p),
                    )
                    continue
                if not stat.S_ISREG(st.st_mode) or st.st_size > max_size:
                    continue
                yield FileEntry(rel=str(p.relative_to(base)), abspath=p,
                                size=st.st_size, mode=st.st_mode)

    def find(self, *rels: str) -> Optional[Path]:
        """Resolve the first of several candidate paths that exists."""
        base = self.root.resolve()
        for rel in rels:
            p = (base / rel.lstrip("/"))
            try:
                if p.resolve().relative_to(base) and p.is_file():
                    return p
            except (ValueError, OSError):
                continue
        return None


@dataclass
class Component:
    """One identified third-party component, for the SBOM."""
    name: str
    version: Optional[str]
    evidence_path: str            # rootfs-relative file it came from
    evidence_offset: int
    source: str                   # "version_string", "package_db", "banner"
    cpe: Optional[str] = None


@dataclass
class Service:
    """A network-facing service inferred from init scripts and configs."""
    name: str
    binary: Optional[str] = None
    port: Optional[int] = None
    proto: str = "tcp"
    autostart: bool = False
    config_paths: list[str] = field(default_factory=list)
    runs_as: Optional[str] = None
    evidence: list[str] = field(default_factory=list)

    @property
    def web(self) -> bool:
        return self.port in (80, 443, 8080, 8443, 8000) or self.name in (
            "lighttpd", "uhttpd", "boa", "goahead", "mini_httpd",
            "thttpd", "nginx", "httpd", "bmcweb", "appweb",
        )


@dataclass
class EmulatedTarget:
    """
    The bridge back to the web lane.

    Once the emulator boots and a service answers, this becomes an ordinary
    Sentinel target and every existing web detector runs against it with no
    modification. Findings produced this way carry `runtime_diff` proofs and
    are the only firmware findings allowed to claim REACHABILITY.
    """
    base_url: str
    rootfs: RootFS
    services: list[Service] = field(default_factory=list)
    boot_log: Optional[Path] = None
    qemu_pid: Optional[int] = None
    network_isolated: bool = True     # never False without explicit scope opt-in


__all__ = ["FirmwareImage", "Partition", "FileEntry", "RootFS",
           "Component", "Service", "EmulatedTarget"]
