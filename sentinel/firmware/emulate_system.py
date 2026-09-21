"""
sentinel.firmware.emulate_system
================================

Full-system emulation for boards QEMU already models.

The user-mode backend in `emulate.py` suits images whose network surface is
CGI binaries: copy a static QEMU in, chroot, invoke the handler. It is the
right tool for a consumer router and the wrong one for a BMC. `bmcweb` does
not parse a request and exit; it expects D-Bus, systemd, an object mapper and
a sensor tree, and under `qemu-arm-static` in a chroot it dies during
initialisation every time. Nothing useful comes of forcing it.

What makes BMCs tractable instead is that QEMU models the hardware. ASPEED
AST2400/2500/2600 boards -- romulus, witherspoon, ast2500-evb, tacoma and
others -- boot their stock flash images directly, so the whole userspace
comes up and the services answer on real sockets. At that point the image is
an ordinary HTTP target and every web detector applies unchanged.

Boot is slow (minutes, not seconds) and frequently fails on a vendor image
that expects hardware QEMU does not model. Both are handled as normal
outcomes: the boot log is kept as an artifact either way, and a failure to
boot is reported as a failure to boot rather than as an absence of findings.

Network posture
---------------
The guest gets SLIRP with `restrict=on`, which blocks everything except the
explicitly forwarded port. A BMC that reaches a vendor endpoint during boot
is making a connection from your address that you did not intend, and the
default here is that it cannot. `Scope.allow_emulated_egress` lifts it, and
nothing else does.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.contracts import Scope
from .models import EmulatedTarget, FirmwareImage, RootFS, Service


class SystemEmulationUnavailable(RuntimeError):
    pass


# Machine types that boot a raw flash image directly, with the flash size the
# board expects. Ordered by how commonly the image is seen in the wild.
ASPEED_MACHINES = {
    "romulus-bmc": {"soc": "ast2500", "flash_mb": 32},
    "witherspoon-bmc": {"soc": "ast2500", "flash_mb": 32},
    "ast2500-evb": {"soc": "ast2500", "flash_mb": 32},
    "swift-bmc": {"soc": "ast2500", "flash_mb": 32},
    "sonorapass-bmc": {"soc": "ast2500", "flash_mb": 32},
    "g220a-bmc": {"soc": "ast2500", "flash_mb": 32},
    "tacoma-bmc": {"soc": "ast2600", "flash_mb": 64},
    "rainier-bmc": {"soc": "ast2600", "flash_mb": 64},
    "ast2600-evb": {"soc": "ast2600", "flash_mb": 64},
    "quanta-q71l-bmc": {"soc": "ast2400", "flash_mb": 32},
    "palmetto-bmc": {"soc": "ast2400", "flash_mb": 32},
    "ast2400-a1": {"soc": "ast2400", "flash_mb": 32},
}

# Lines that mean userspace is up, and lines that mean it never will be.
BOOT_READY = (b"login:", b"systemd[1]: Startup finished",
              b"Reached target Multi-User", b"Started bmcweb")
BOOT_FATAL = (b"Kernel panic", b"Unable to mount root fs",
              b"VFS: Cannot open root device", b"end Kernel panic")


def available_machines() -> list[str]:
    """Machines this QEMU build actually knows about."""
    qemu = shutil.which("qemu-system-arm")
    if not qemu:
        return []
    try:
        out = subprocess.run([qemu, "-M", "help"], capture_output=True,
                             timeout=30, text=True).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    return [m.group(1) for line in out.splitlines()
            if (m := re.match(r"^(\S+)\s", line))]


def guess_machine(image: FirmwareImage, rootfs: Optional[RootFS] = None,
                  hint: str | None = None) -> str | None:
    """
    Pick a machine type from the image, preferring evidence over guesswork.

    The device tree name inside the image is the strongest signal -- an
    OpenBMC build carries its board name in the fdt and in several
    filesystem paths, so we look there before falling back to flash size,
    which only narrows it to a SoC generation.
    """
    known = set(available_machines())
    if hint:
        return hint if hint in known else None

    names: list[str] = []
    if rootfs is not None:
        for rel in ("etc/os-release", "etc/version", "usr/share/bmcweb/version"):
            p = rootfs.find(rel)
            if p:
                names.append(p.read_text("utf-8", "replace").lower())

    head = image.path.read_bytes()[: 8 << 20].lower()
    for machine in ASPEED_MACHINES:
        board = machine.rsplit("-", 1)[0].encode()
        if machine not in known:
            continue
        if board in head or any(board.decode() in n for n in names):
            return machine

    size_mb = image.size / (1 << 20)
    for machine, spec in ASPEED_MACHINES.items():
        if machine in known and abs(spec["flash_mb"] - size_mb) < 2:
            return machine
    return None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@dataclass
class AspeedSystemBackend:
    """
    Boots a raw BMC flash image under qemu-system-arm.

    The image is copied and padded to the board's flash size first. QEMU
    rejects an MTD backing file that is not exactly the expected size, and
    padding the original in place would corrupt evidence that earlier stages
    already hashed into proofs.
    """
    image: FirmwareImage
    scope: Scope
    workdir: Path
    machine: str
    guest_port: int = 443
    boot_timeout: int = 420
    _proc: Optional[subprocess.Popen] = field(default=None, init=False)
    _host_port: Optional[int] = field(default=None, init=False)
    _log: Optional[Path] = field(default=None, init=False)

    def _staged_flash(self) -> Path:
        spec = ASPEED_MACHINES[self.machine]
        want = spec["flash_mb"] << 20
        dest = self.workdir / f"flash-{spec['flash_mb']}M.img"
        self.workdir.mkdir(parents=True, exist_ok=True)
        data = self.image.path.read_bytes()
        if len(data) > want:
            raise SystemEmulationUnavailable(
                f"image is {len(data)/1e6:.1f} MB, larger than {self.machine}'s "
                f"{spec['flash_mb']} MB flash; wrong machine type")
        dest.write_bytes(data + b"\xff" * (want - len(data)))
        return dest

    def start(self) -> EmulatedTarget:
        qemu = shutil.which("qemu-system-arm")
        if not qemu:
            raise SystemEmulationUnavailable(
                "qemu-system-arm not installed (apt install qemu-system-arm)")
        if self.machine not in available_machines():
            raise SystemEmulationUnavailable(
                f"this QEMU build has no {self.machine!r} machine")

        flash = self._staged_flash()
        self._host_port = _free_port()
        self._log = self.workdir / "boot.log"

        # restrict=on blocks everything the guest tries except the forwarded
        # port. Without it, SLIRP happily NATs the BMC onto your network.
        # The ftgmac100 is part of the ASPEED SoC model, created with the
        # machine, so it cannot be added with -device. -nic attaches the
        # backend to the NIC the machine already has.
        netdev = (f"user,restrict="
                  f"{'off' if self.scope.allow_emulated_egress else 'on'},"
                  f"hostfwd=tcp:127.0.0.1:{self._host_port}-:{self.guest_port}")

        cmd = [
            qemu, "-M", self.machine, "-nographic", "-no-reboot",
            "-drive", f"file={flash},format=raw,if=mtd",
            "-nic", netdev,
            "-serial", f"file:{self._log}",
            "-monitor", "none",
        ]
        self._proc = subprocess.Popen(
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, start_new_session=True,
        )
        return EmulatedTarget(
            base_url=f"https://127.0.0.1:{self._host_port}",
            rootfs=None,  # filled in by the caller if it has one
            network_isolated=not self.scope.allow_emulated_egress,
            boot_log=self._log,
            qemu_pid=self._proc.pid,
        )

    def wait_for_boot(self, poll: float = 3.0) -> tuple[bool, str]:
        """
        Block until the forwarded port answers, the log says it never will,
        or the timeout expires. Returns (booted, reason).
        """
        assert self._proc and self._log and self._host_port
        deadline = time.time() + self.boot_timeout
        while time.time() < deadline:
            if self._proc.poll() is not None:
                err = (self._proc.stderr.read().decode("utf-8", "replace")
                       if self._proc.stderr else "")
                return False, f"qemu exited early: {err.strip()[:300]}"

            log = self._log.read_bytes() if self._log.is_file() else b""
            if any(f in log for f in BOOT_FATAL):
                hit = next(f for f in BOOT_FATAL if f in log)
                return False, f"kernel failure: {hit.decode()}"

            with socket.socket() as s:
                s.settimeout(2)
                if s.connect_ex(("127.0.0.1", self._host_port)) == 0:
                    return True, f"port {self.guest_port} answering"

            if any(r in log for r in BOOT_READY):
                # Userspace is up but nothing is listening yet. Keep waiting;
                # bmcweb binds well after multi-user on a slow emulated core.
                pass
            time.sleep(poll)

        size = self._log.stat().st_size if self._log.is_file() else 0
        return False, (f"no listener after {self.boot_timeout}s "
                       f"(boot log {size} bytes -- read it before assuming "
                       f"the image is at fault)")

    def stop(self) -> None:
        if not self._proc:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None


__all__ = ["AspeedSystemBackend", "SystemEmulationUnavailable",
           "available_machines", "guess_machine", "ASPEED_MACHINES"]
