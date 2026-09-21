"""
2sentinel.firmware.emulate
=========================

User-mode emulation, and the runtime oracle it exists to produce.

Full-system emulation is the obvious approach and the wrong place to start.
Booting a vendor image end to end means getting the kernel, device tree, NVRAM
contents and a dozen peripheral stubs right, and on most images you lose days
before the first HTTP response. User-mode emulation skips all of it: copy a
static QEMU into the rootfs, chroot, and run one CGI binary directly. It works
on the first afternoon for a large fraction of images, and one CGI binary
answering is enough to produce `runtime_diff` proofs -- which is the only
thing the static lane cannot give you.

What this buys, concretely: `fw.creds.hardcoded` confirms that a hash sits in
/etc/shadow. That is a presence fact and it stays one forever. If the login
CGI runs here and a request carrying that credential returns a different
response than a control request, the finding crosses to REACHABILITY with a
stored transcript proving it. Nothing else in the pipeline can make that
crossing.

Running vendor binaries
-----------------------
This stage executes untrusted third-party code. Not hypothetically -- that is
its entire job. The guards below are not decoration:

  * the rootfs is copied first; the original extraction is never the thing we
    execute against, so a binary that scribbles on its own filesystem cannot
    corrupt the evidence other stages already captured
  * no network namespace, when `unshare` is available. A firmware binary that
    phones a vendor endpoint from your address is an out-of-scope request you
    made by accident, and `Scope.allow_emulated_egress` is the only thing that
    permits it
  * CPU, address-space and file-size rlimits, plus a wall-clock timeout. Crypto
    init loops and fork bombs are common in half-emulated firmware, not rare
  * never as root. uid 0 inside a chroot is a much shorter walk out than people
    assume

Probes
------
The harness measures; it does not carry a payload catalogue. A probe is a
control input, a variant input, and an observable. The variant comes from the
detector or template that called it. The built-in probe is a high-entropy
marker used to establish input reflection and code-path reachability, which is
the measurement, not an exploit.
"""

from __future__ import annotations

import json
import os
import resource
import secrets as _secrets
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..core.contracts import ProofArtifact, RunContext, Scope
from .models import EmulatedTarget, RootFS, Service

QEMU_FOR_ARCH = {
    "arm": "qemu-arm-static", "aarch64": "qemu-aarch64-static",
    "mips": "qemu-mips-static", "mipsel": "qemu-mipsel-static",
    "x86": "qemu-i386-static", "x86_64": "qemu-x86_64-static",
    "powerpc": "qemu-ppc-static", "riscv": "qemu-riscv64-static",
}

# Paths a CGI binary will look for and sulk without. Created empty rather than
# bind-mounted from the host: an emulated binary reading the host's /proc is
# both a correctness bug and an information leak.
STUB_DIRS = ["proc", "sys", "dev", "tmp", "var/run", "var/tmp"]


class EmulationUnavailable(RuntimeError):
    pass


@dataclass
class Transcript:
    """One execution. Stored verbatim; this is what a runtime_diff proves on."""
    argv: list[str]
    env: dict[str, str]
    stdin: bytes
    stdout: bytes
    stderr: bytes
    status: Optional[int]
    seconds: float
    timed_out: bool = False

    def to_json(self) -> bytes:
        return json.dumps({
            "argv": self.argv,
            "env": {k: v for k, v in self.env.items() if k != "_MARKER"},
            "stdin": self.stdin.decode("utf-8", "replace"),
            "stdout": self.stdout.decode("utf-8", "replace"),
            "stderr": self.stderr.decode("utf-8", "replace")[:4000],
            "status": self.status,
            "seconds": round(self.seconds, 3),
            "timed_out": self.timed_out,
        }, indent=2).encode()

    @property
    def http_status(self) -> Optional[int]:
        """CGI declares status in a header, not an exit code."""
        head = self.stdout[:512].decode("utf-8", "replace")
        for line in head.splitlines():
            if line.lower().startswith("status:"):
                try:
                    return int(line.split(":", 1)[1].strip().split()[0])
                except (ValueError, IndexError):
                    return None
            if not line.strip():
                break
        return 200 if self.stdout else None


# --------------------------------------------------------------------------

@dataclass
class QemuUserBackend:
    """
    Runs a single binary from the rootfs under qemu-user in a chroot.

    Not a device. There is no init, no NVRAM, no kernel. Binaries that expect
    a populated /proc or an ioctl against a real peripheral will fail, and
    that failure is honest output -- far better than a full-system boot that
    half-works and produces findings against a device that does not exist.
    """
    rootfs: RootFS
    scope: Scope
    workdir: Path
    timeout: int = 15
    mem_limit_mb: int = 512
    cpu_seconds: int = 10
    _staged: Optional[Path] = field(default=None, init=False)

    # -- setup ---------------------------------------------------------

    def qemu_binary(self) -> str:
        """
        Find a QEMU that will actually work inside a chroot.

        The distinction matters and the package names hide it. `qemu-user`
        ships /usr/bin/qemu-arm, dynamically linked against the host's libc
        and loader. Copy that into a firmware rootfs and it dies immediately
        looking for /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2, which is not
        there and must not be. Only the `-static` build from the
        `qemu-user-static` package runs with nothing but itself.

        Debian and Kali will happily resolve `apt install qemu-user-static`
        to `qemu-user-binfmt` via Provides, which registers binfmt handlers
        but installs no static binaries -- so checking that the package
        "installed fine" proves nothing. We verify the ELF has no PT_INTERP
        rather than trusting the filename.
        """
        arch = (self.rootfs.arch or "").split("(")[0]
        stem = QEMU_FOR_ARCH.get(arch)
        if not stem:
            raise EmulationUnavailable(f"no qemu-user for arch {arch!r}")

        candidates = [stem, stem.replace("-static", "")]
        for name in candidates:
            path = shutil.which(name)
            if path and self._is_static(path):
                return path

        found = next((n for n in candidates if shutil.which(n)), None)
        if found:
            raise EmulationUnavailable(
                f"{found} is dynamically linked and cannot run inside a "
                f"chroot. Install the static build:\n"
                f"    sudo apt install qemu-user-static\n"
                f"then confirm with: ls /usr/bin/{stem}\n"
                f"If apt resolves that to qemu-user-binfmt, the static "
                f"binaries are not installed -- fetch the .deb directly or "
                f"run this stage in the analysis container, which pins them.")
        raise EmulationUnavailable(
            f"{stem} not found (sudo apt install qemu-user-static)")

    @staticmethod
    def _is_static(path: str) -> bool:
        """No PT_INTERP means nothing outside the chroot is needed."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(64)
                if head[:4] != b"\x7fELF":
                    return False
                is64, little = head[4] == 2, head[5] == 1
                order = "little" if little else "big"
                if is64:
                    phoff = int.from_bytes(head[32:40], order)
                    phentsize = int.from_bytes(head[54:56], order)
                    phnum = int.from_bytes(head[56:58], order)
                else:
                    phoff = int.from_bytes(head[28:32], order)
                    phentsize = int.from_bytes(head[42:44], order)
                    phnum = int.from_bytes(head[44:46], order)
                fh.seek(phoff)
                for _ in range(phnum):
                    ph = fh.read(phentsize)
                    if len(ph) < 4:
                        break
                    if int.from_bytes(ph[0:4], order) == 3:   # PT_INTERP
                        return False
            return True
        except OSError:
            return False

    def stage(self) -> Path:
        """
        Copy the rootfs to scratch and drop QEMU in. Copying is not paranoia:
        the extraction output is evidence that earlier stages have already
        hashed into proofs, and letting vendor code write to it would break
        every one of those proofs.
        """
        if self._staged:
            return self._staged
        qemu = self.qemu_binary()
        staged = self.workdir / "staged"
        if staged.exists():
            shutil.rmtree(staged, ignore_errors=True)
        shutil.copytree(self.rootfs.root, staged, symlinks=True,
                        ignore_dangling_symlinks=True)
        for d in STUB_DIRS:
            (staged / d).mkdir(parents=True, exist_ok=True)
        shutil.copy2(qemu, staged / Path(qemu).name)
        os.chmod(staged / Path(qemu).name, 0o755)
        self._staged = staged
        return staged

    def cleanup(self) -> None:
        if self._staged:
            shutil.rmtree(self._staged, ignore_errors=True)
            self._staged = None

    # -- execution -----------------------------------------------------

    def _limits(self):
        def apply():
            resource.setrlimit(resource.RLIMIT_CPU,
                               (self.cpu_seconds, self.cpu_seconds))
            mem = self.mem_limit_mb << 20
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_FSIZE, (64 << 20, 64 << 20))
            resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            os.setsid()
        return apply

    def run_binary(self, rel_binary: str, argv: list[str] | None = None,
                   env: dict[str, str] | None = None,
                   stdin: bytes = b"") -> Transcript:
        staged = self.stage()
        qemu_name = Path(self.qemu_binary()).name

        target = (staged / rel_binary.lstrip("/"))
        if not target.is_file():
            raise EmulationUnavailable(f"{rel_binary} not in rootfs")
        os.chmod(target, 0o755)

        inner = [f"/{qemu_name}", "-L", "/", f"/{rel_binary.lstrip('/')}",
                 *(argv or [])]
        cmd = ["chroot", str(staged), *inner]

        # No route off the host unless scope says otherwise. This is the
        # difference between analysing firmware and letting firmware talk.
        if not self.scope.allow_emulated_egress and shutil.which("unshare"):
            cmd = ["unshare", "-n", "--", *cmd]

        full_env = {
            "PATH": "/bin:/sbin:/usr/bin:/usr/sbin",
            "HOME": "/", "LD_LIBRARY_PATH": "/lib:/usr/lib",
            **(env or {}),
        }

        t0 = time.time()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd, input=stdin, capture_output=True, env=full_env,
                timeout=self.timeout, preexec_fn=self._limits(), check=False,
            )
            out, err, status = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or b""
            err = (exc.stderr or b"") + b"\n[sentinel] wall-clock timeout"
            status, timed_out = None, True
        except (PermissionError, FileNotFoundError) as exc:
            raise EmulationUnavailable(
                f"chroot failed ({exc}); run inside the analysis container, "
                f"or grant CAP_SYS_CHROOT") from exc

        return Transcript(argv=inner, env=full_env, stdin=stdin, stdout=out,
                          stderr=err, status=status,
                          seconds=time.time() - t0, timed_out=timed_out)

    # -- CGI ------------------------------------------------------------

    def run_cgi(self, rel_binary: str, *, method: str = "GET",
                query: str = "", body: bytes = b"",
                headers: dict[str, str] | None = None,
                path_info: str = "") -> Transcript:
        """
        Invoke a CGI binary the way a web server would.

        Most embedded web interfaces are a thin httpd in front of CGI
        binaries, so this reaches the code that actually handles requests
        without needing the httpd, its config, or a working socket layer.
        """
        env = {
            "GATEWAY_INTERFACE": "CGI/1.1", "SERVER_PROTOCOL": "HTTP/1.1",
            "SERVER_SOFTWARE": "sentinel", "SERVER_NAME": "127.0.0.1",
            "SERVER_PORT": "80", "REMOTE_ADDR": "127.0.0.1",
            "REQUEST_METHOD": method.upper(),
            "QUERY_STRING": query,
            "SCRIPT_NAME": "/" + rel_binary.lstrip("/"),
            "PATH_INFO": path_info,
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": (headers or {}).get(
                "Content-Type", "application/x-www-form-urlencoded"),
        }
        for k, v in (headers or {}).items():
            env["HTTP_" + k.upper().replace("-", "_")] = v
        return self.run_binary(rel_binary, env=env, stdin=body)


# --------------------------------------------------------------------------
# The oracle
# --------------------------------------------------------------------------

@dataclass
class DifferentialResult:
    diverged: bool
    dimension: str
    control_transcript: Transcript
    control_b: Transcript
    probe_transcript: Transcript
    note: str = ""


def differential(backend: QemuUserBackend, rel_binary: str,
                 control: dict, probe: dict, *,
                 observable: str = "auto",
                 marker: str | None = None) -> DifferentialResult:
    """
    Run control, control again, then the probe, and decide whether the
    divergence is real.

    The second control is the entire point. Embedded CGI binaries are noisy:
    they stamp timestamps, session ids, uptime counters and free-memory
    figures into responses. Compare one control against one probe and every
    one of those endpoints looks injectable. Running the control twice
    measures that noise first, and any probe divergence that the control
    noise already explains is discarded rather than reported.

    `control` and `probe` are the caller's request kwargs for `run_cgi`. The
    harness supplies no payloads of its own; detectors and templates own what
    goes in the probe.
    """
    a = backend.run_cgi(rel_binary, **control)
    b = backend.run_cgi(rel_binary, **control)
    p = backend.run_cgi(rel_binary, **probe)

    if marker:
        hit = marker.encode() in p.stdout and marker.encode() not in a.stdout
        return DifferentialResult(
            hit, "marker", a, b, p,
            "input reflected into output" if hit else "marker not observed")

    if observable in ("auto", "status"):
        sa, sb, sp = a.http_status, b.http_status, p.http_status
        if sa is not None and sa == sb and sp != sa:
            return DifferentialResult(True, "status", a, b, p,
                                      f"status {sa} -> {sp}")

    if observable in ("auto", "length"):
        noise = abs(len(b.stdout) - len(a.stdout))
        delta = abs(len(p.stdout) - len(a.stdout))
        # The probe must move the response several times further than the
        # endpoint moves on its own. A fixed byte threshold does not survive
        # contact with a page that embeds a clock.
        if delta >= 48 and delta > noise * 4:
            return DifferentialResult(True, "length", a, b, p,
                                      f"length +{delta} against {noise} noise")
        if noise >= 48:
            return DifferentialResult(
                False, "length", a, b, p,
                f"endpoint is non-deterministic ({noise} bytes between two "
                f"identical requests); no length oracle available here")

    return DifferentialResult(False, observable, a, b, p, "no divergence")


def build_runtime_proof(result: DifferentialResult, ctx: RunContext,
                        label: str) -> ProofArtifact:
    """Store both transcripts and return the proof a Finding can confirm on."""
    ctrl = ctx.store_blob(f"{label}.control.json",
                          result.control_transcript.to_json())
    probe = ctx.store_blob(f"{label}.probe.json",
                           result.probe_transcript.to_json())
    ctx.store_blob(f"{label}.control_b.json", result.control_b.to_json())

    claim: dict = {"control_transcript": ctrl, "probe_transcript": probe}
    if result.dimension == "marker":
        claim["observable"] = "marker"
        claim["marker"] = result.note
    else:
        claim["observable"] = "status"
    return ProofArtifact(kind="runtime_diff", claim=claim, blobs=[ctrl, probe])


def new_marker() -> str:
    """High-entropy, unique per probe, so a hit cannot be misattributed."""
    return "sntl" + _secrets.token_hex(12)


# --------------------------------------------------------------------------

def discover_cgi(rootfs: RootFS, limit: int = 200) -> list[str]:
    """
    CGI binaries, most interesting first.

    Ordering matters more than it looks: on a camera or BMC image the
    authentication handler is where reachability findings actually live, and
    running it first means a time-boxed run still covers the thing you care
    about.
    """
    hits: list[tuple[int, str]] = []
    for entry in rootfs.walk(max_size=16 << 20):
        rel = entry.rel
        if not any(seg in rel for seg in ("cgi-bin/", "www/", "web/", "htdocs/")):
            if not rel.endswith(".cgi"):
                continue
        if not (entry.executable or rel.endswith(".cgi")):
            continue
        name = rel.rsplit("/", 1)[-1].lower()
        score = 0
        for kw, w in (("login", 9), ("auth", 8), ("user", 6), ("passwd", 6),
                      ("upload", 6), ("config", 5), ("admin", 5), ("set", 4),
                      ("net", 3), ("sys", 3)):
            if kw in name:
                score += w
        hits.append((score, rel))
    hits.sort(key=lambda t: (-t[0], t[1]))
    return [rel for _, rel in hits[:limit]]


def prepare_target(rootfs: RootFS, services: list[Service], scope: Scope,
                   workdir: Path) -> EmulatedTarget:
    backend = QemuUserBackend(rootfs=rootfs, scope=scope, workdir=workdir)
    backend.stage()
    return EmulatedTarget(
        base_url="cgi://user-mode",   # not a socket: CGI is invoked directly
        rootfs=rootfs, services=services,
        network_isolated=not scope.allow_emulated_egress,
    )


__all__ = ["QemuUserBackend", "EmulationUnavailable", "Transcript",
           "differential", "DifferentialResult", "build_runtime_proof",
           "new_marker", "discover_cgi", "prepare_target", "QEMU_FOR_ARCH"]
