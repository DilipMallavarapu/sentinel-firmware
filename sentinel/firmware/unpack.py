"""
sentinel.firmware.unpack
Extraction and rootfs identification.
Order of preference: unblob (best recursive extraction, structured JSON
report), then binwalk -Me, then a magic-scan fallback that carves known
container headers directly. Whichever runs, the output is normalised to the
same `Partition` list so downstream stages never learn which tool won.
Two things this stage must get right, because everything after depends on it:
Finding the real rootfs. A binwalk run on a vendor image typically
produces a dozen candidate directories, most of them fragments. Picking
wrong means every later analyzer reports nothing and the run looks clean
when it is actually blind. We score candidates on filesystem-shape
evidence rather than trusting extraction order.
Flagging encryption instead of silently producing nothing. A vendor image
with a high-entropy unidentified blob is a finding in itself (and a signal
the researcher needs the key from a bootloader dump). An analyzer that
returns zero findings on an encrypted image is the worst possible false
negative, so we surface it loudly.
"""
from __future__ import annotations
import json
import math
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from .models import FirmwareImage, Partition, RootFS

MAGICS: list[tuple[bytes, str]] = [
    (b"hsqs", "squashfs"), (b"sqsh", "squashfs"),
    (b"\x73\x71\x73\x68", "squashfs"),
    (b"\x28\xcd\x3d\x45", "cramfs"),
    (b"\x19\x85\x20\x03", "jffs2"),
    (b"UBI#", "ubi"), (b"\x31\x18\x10\x06", "ubifs"),
    (b"\x27\x05\x19\x56", "uimage"),
    (b"\xd0\x0d\xfe\xed", "dtb"),
    (b"\x1f\x8b\x08", "gzip"), (b"\xfd7zXZ\x00", "xz"),
    (b"\x04\x22\x4d\x18", "lz4"), (b"\x28\xb5\x2f\xfd", "zstd"),
]

ROOTFS_MARKERS = [
    ("bin/busybox", 6), ("etc/passwd", 5), ("etc/shadow", 5),
    ("etc/init.d", 4), ("sbin/init", 4), ("lib/ld-uClibc.so.0", 4),
    ("usr/bin", 2), ("etc/", 2), ("www/", 3), ("var/", 1), ("dev/", 1),
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


# --------------------------------------------------------------------------

def extract(image: FirmwareImage, workdir: Path,
            timeout: int = 1800) -> tuple[list[Partition], str]:
    """Run the best available extractor. Returns (partitions, tool_used)."""
    workdir.mkdir(parents=True, exist_ok=True)
    if _have("unblob"):
        parts = _unblob(image, workdir, timeout)
        if parts:
            return parts, "unblob"
    if _have("binwalk"):
        parts = _binwalk(image, workdir, timeout)
        if parts:
            return parts, "binwalk"
    return _carve(image, workdir), "carve"


def _unblob(image: FirmwareImage, workdir: Path, timeout: int) -> list[Partition]:
    out = workdir / "unblob"
    cmd = ["unblob", "--extract-dir", str(out), "--report",
           str(workdir / "unblob.json"), "--depth", "8", str(image.path)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return []
    report = workdir / "unblob.json"
    parts: list[Partition] = []
    if report.is_file():
        try:
            for i, rec in enumerate(json.loads(report.read_text())):
                if rec.get("typename") not in ("ChunkReport", "Chunk"):
                    continue
                parts.append(Partition(
                    index=i,
                    offset=int(rec.get("start_offset", 0)),
                    size=int(rec.get("end_offset", 0)) - int(rec.get("start_offset", 0)),
                    kind=(rec.get("handler_name") or "unknown").lower(),
                ))
        except Exception:
            pass
    if not parts and out.is_dir():
        parts = [Partition(index=0, offset=0, size=image.size,
                           kind="unknown", extracted_to=out)]
    for p in parts:
        p.extracted_to = p.extracted_to or out
    return parts


def _binwalk(image: FirmwareImage, workdir: Path, timeout: int) -> list[Partition]:
    try:
        proc = subprocess.run(
            ["binwalk", "-Me", "--directory", str(workdir), str(image.path)],
            capture_output=True, timeout=timeout, check=False, text=True,
        )
    except subprocess.TimeoutExpired:
        return []
    parts: list[Partition] = []
    for i, line in enumerate(proc.stdout.splitlines()):
        m = re.match(r"^\s*(\d+)\s+0x[0-9A-Fa-f]+\s+(.+)$", line)
        if not m:
            continue
        desc = m.group(2).strip()
        kind = "unknown"
        for key in ("squashfs", "cramfs", "jffs2", "ubi", "uimage",
                     "gzip", "xz", "lzma", "device tree"):
            if key in desc.lower():
                kind = key.replace("  ", " ")
                break
        parts.append(Partition(index=i, offset=int(m.group(1)), size=0, kind=kind))
    extracted = next((d for d in workdir.glob("_*.extracted") if d.is_dir()), None)
    for p in parts:
        p.extracted_to = extracted
    return parts


def _carve(image: FirmwareImage, workdir: Path) -> list[Partition]:
    """
    Last resort. Scans for container magics and records offsets so the
    researcher at least knows where to point `dd`. No extraction attempted --
    a half-extracted filesystem is worse than an honest "install unblob".
    """
    data = image.path.read_bytes()
    parts: list[Partition] = []
    for i, (magic, kind) in enumerate(MAGICS):
        start = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            parts.append(Partition(index=len(parts), offset=idx, size=0, kind=kind))
            start = idx + 1
            if len(parts) > 512:
                break
    win = 64 << 10
    for off in range(0, min(len(data), 32 << 20), win):
        e = _entropy(data[off:off + win])
        if e > 7.95:
            parts.append(Partition(index=len(parts), offset=off, size=win,
                                   kind="high_entropy", entropy=e))
    return parts


# --------------------------------------------------------------------------

def locate_rootfs(search_root: Path) -> tuple[Path | None, dict]:
    """
    Score every extracted directory on how much it looks like a Linux root.
    """
    scores: dict[str, int] = {}
    for cand in [search_root, *(d for d in search_root.rglob("*") if d.is_dir())]:
        score = 0
        for marker, weight in ROOTFS_MARKERS:
            if (cand / marker).exists():
                score += weight
        if score:
            scores[str(cand)] = score
    if not scores:
        return None, {}
    best = max(scores.items(), key=lambda kv: (kv[1], -len(kv[0])))
    return (Path(best[0]) if best[1] >= 6 else None), scores


def identify(rootfs: RootFS) -> RootFS:
    """Fill in arch/endian/libc/init from cheap, high-confidence signals."""
    probe = rootfs.find("bin/busybox", "sbin/init", "bin/sh", "bin/login")
    if probe:
        head = probe.read_bytes()[:64]
        if head[:4] == b"\x7fELF":
            rootfs.endian = "little" if head[5] == 1 else "big"
            machine = int.from_bytes(head[18:20], rootfs.endian)
            rootfs.arch = {
                0x28: "arm", 0xB7: "aarch64", 0x08: "mips", 0x03: "x86",
                0x3E: "x86_64", 0x14: "powerpc", 0xF3: "riscv",
            }.get(machine, f"unknown(0x{machine:x})")
            if rootfs.arch == "mips" and rootfs.endian == "little":
                rootfs.arch = "mipsel"
    if rootfs.find("lib/ld-uClibc.so.0", "lib/libuClibc.so.0"):
        rootfs.libc = "uclibc"
    elif (rootfs.root / "lib").is_dir() and any(
            (rootfs.root / "lib").glob("ld-musl-*.so.*")):
        # ld-musl-<arch>.so.1 where <arch> is mipsel-sf, armhf, x86_64 and a
        # dozen others. Naming two of them meant every musl MIPS image --
        # most of OpenWrt -- reported an unknown libc.
        rootfs.libc = "musl"
    elif rootfs.find("lib/libc.so.6"):
        rootfs.libc = "glibc"
    if (rootfs.root / "etc/init.d").is_dir():
        rootfs.init_system = "procd" if rootfs.find("sbin/procd") else "sysvinit"
    elif (rootfs.root / "lib/systemd").is_dir():
        rootfs.init_system = "systemd"
    elif rootfs.find("bin/busybox"):
        rootfs.init_system = "busybox"
    return rootfs


__all__ = ["extract", "locate_rootfs", "identify", "MAGICS"]
