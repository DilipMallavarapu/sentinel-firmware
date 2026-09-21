"""
sentinel.cli
============

    python3 -m sentinel.cli firmware --image images/DS-K1T671M.bin \
        --scope HSRC-2026-014 --authorize-sha auto --serve

Scope is mandatory and positional in spirit: there is no flag that runs the
pipeline without an authorization reference, because the reference is what
goes in the report and what you point at if a vendor asks why you had their
firmware. `--authorize-sha auto` pins the scope to whatever the image hashes
to right now and prints it so you can paste it into your notes; pass an
explicit hash instead when you want the run to fail loudly if someone hands
you a different file than the one you were authorized to look at.
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core.contracts import Scope
from .firmware.models import FirmwareImage
from .firmware.pipeline import analyze_firmware

UI_DIR = Path(__file__).resolve().parent.parent / "ui"


# --------------------------------------------------------------------------
# SSE fan-out
# --------------------------------------------------------------------------

class EventBus:
    """
    One queue per connected dashboard. Slow clients get dropped rather than
    backing up the pipeline -- a stalled browser tab must never be able to
    pause a firmware run.
    """

    def __init__(self, replay: int = 500):
        self._subs: list[queue.Queue] = []
        self._log: list[tuple[str, dict]] = []
        self._replay = replay
        self._lock = threading.Lock()

    def emit(self, event: str, data: dict) -> None:
        with self._lock:
            self._log.append((event, data))
            del self._log[:-self._replay]
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait((event, data))
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subs.remove(q)

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=2000)
        with self._lock:
            for item in self._log:     # late joiners see the run so far
                q.put_nowait(item)
            self._subs.append(q)
        return q


def make_handler(bus: EventBus):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):    # quiet; the dashboard is the log
            pass

        def do_GET(self):
            if self.path.startswith("/stream"):
                return self._stream()
            return self._static()

        def _stream(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = bus.subscribe()
            try:
                while True:
                    try:
                        event, data = q.get(timeout=15)
                        frame = (f"event: {event}\n"
                                 f"data: {json.dumps(data, default=str)}\n\n")
                    except queue.Empty:
                        frame = ": keepalive\n\n"
                    self.wfile.write(frame.encode())
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _static(self):
            name = "firmware_run.html" if self.path in ("/", "") \
                else Path(self.path).name
            path = (UI_DIR / name).resolve()
            try:
                path.relative_to(UI_DIR.resolve())
                body = path.read_bytes()
            except (ValueError, OSError):
                self.send_error(404)
                return
            ctype = {"html": "text/html", "js": "text/javascript",
                     "css": "text/css"}.get(name.rsplit(".", 1)[-1],
                                            "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", f"{ctype}; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


# --------------------------------------------------------------------------

def cmd_firmware(args: argparse.Namespace) -> int:
    image_path = Path(args.image)
    if not image_path.is_file():
        print(f"no such image: {image_path}", file=sys.stderr)
        return 2

    if args.authorize_sha == "auto":
        digest = FirmwareImage.from_file(image_path).sha256
        print(f"image sha256: {digest}\n"
              f"  pinning scope {args.scope!r} to this hash for the run")
        shas = [digest]
    elif args.authorize_sha:
        shas = [args.authorize_sha]
    else:
        shas = []
        print("warning: no --authorize-sha; the scope check cannot verify "
              "this is the file you were authorized to analyse",
              file=sys.stderr)

    scope = Scope(
        authorization_ref=args.scope,
        firmware_sha256=shas,
        allow_emulated_egress=args.allow_egress,
    )
    if args.allow_egress:
        print("warning: emulated guest has egress. Vendor firmware can now "
              "reach the network from your address.", file=sys.stderr)

    bus = EventBus()
    if args.serve:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(bus))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"dashboard: http://127.0.0.1:{args.port}/")
        if args.wait:
            input("open it, then press enter to start the run… ")

    def emit(event: str, data: dict) -> None:
        bus.emit(event, data)
        if event == "checkpoint.state":
            print(f"  [{data.get('state','?'):<8}] {data.get('id','')}"
                  f"  {data.get('note','')}")

    run = analyze_firmware(
        image_path, scope,
        workdir=args.workdir,
        emit=emit,
        resume=not args.no_resume,
        emulation_backend=args.emulation_backend,
        bin_dir=args.bin_dir,
    )

    report = run.root / "report.json"
    print(f"\nreport: {report}")
    if args.serve and not args.wait:
        print("dashboard still serving; ctrl-c to stop")
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser("sentinel", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    fw = sub.add_parser("firmware", help="analyse a firmware image")
    fw.add_argument("--image", required=True)
    fw.add_argument("--scope", required=True,
                    help="authorization reference, e.g. a bounty program ID "
                         "or an HSRC case number")
    fw.add_argument("--authorize-sha", default="auto",
                    help="'auto' to pin to this file, or an explicit sha256")
    fw.add_argument("--workdir", default="runs")
    fw.add_argument("--bin-dir", default="bin")
    fw.add_argument("--emulation-backend", default=None,
                    choices=[None, "qemu-user", "qemu-system", "firmae"])
    fw.add_argument("--allow-egress", action="store_true",
                    help="let the emulated guest reach the network. Requires "
                         "explicit authorization; off by default.")
    fw.add_argument("--serve", action="store_true", help="run the dashboard")
    fw.add_argument("--port", type=int, default=8089)
    fw.add_argument("--wait", action="store_true",
                    help="pause until you have the dashboard open")
    fw.add_argument("--no-resume", action="store_true",
                    help="ignore cached checkpoints and redo every stage")
    fw.set_defaults(func=cmd_firmware)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
