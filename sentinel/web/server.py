"""
sentinel.web.server
Local web interface for running firmware scans and viewing results.
"""
from __future__ import annotations
import json
import queue
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..core.contracts import Scope
from ..firmware.pipeline import analyze_firmware


class ScanManager:
    """Manages active scans and broadcasts SSE events."""
    
    def __init__(self):
        self.active_scans: dict[str, dict] = {}
        self.event_queues: list[queue.Queue] = []
        self.lock = threading.Lock()
    
    def start_scan(self, image_path: str, scope_ref: str, 
                   firmware_sha256: list[str] | None = None) -> str:
        """Start a new scan in a background thread."""
        run_id = f"web_{int(time.time())}"
        
        def emit(event: str, data: dict):
            """Broadcast event to all connected SSE clients."""
            payload = json.dumps({"type": event, **data})
            with self.lock:
                for q in self.event_queues:
                    try:
                        q.put_nowait(payload)
                    except queue.Full:
                        pass
        
        scope = Scope(
            authorization_ref=scope_ref,
            firmware_sha256=firmware_sha256 or [],
            domains=["localhost"],
        )
        
        self.active_scans[run_id] = {
            "status": "running",
            "image": image_path,
            "scope": scope_ref,
            "started_at": time.time(),
        }
        
        def run_scan():
            try:
                analyze_firmware(
                    image_path=image_path,
                    scope=scope,
                    workdir="runs",
                    emit=emit,
                    resume=False,
                )
                self.active_scans[run_id]["status"] = "completed"
                emit("run.complete", {"run_id": run_id})
            except Exception as e:
                self.active_scans[run_id]["status"] = "failed"
                self.active_scans[run_id]["error"] = str(e)
                emit("run.error", {"run_id": run_id, "error": str(e)})
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()
        
        return run_id
    
    def subscribe(self) -> queue.Queue:
        """Create a new event queue for an SSE client."""
        q = queue.Queue(maxsize=100)
        with self.lock:
            self.event_queues.append(q)
        return q
    
    def unsubscribe(self, q: queue.Queue):
        """Remove an event queue."""
        with self.lock:
            if q in self.event_queues:
                self.event_queues.remove(q)
    
    def get_runs(self) -> list[dict]:
        """List all completed runs."""
        runs_dir = Path("runs")
        if not runs_dir.exists():
            return []
        
        runs = []
        for run_dir in sorted(runs_dir.iterdir(), reverse=True):
            if not run_dir.is_dir():
                continue
            report_file = run_dir / "report.json"
            if report_file.exists():
                try:
                    report = json.loads(report_file.read_text())
                    runs.append({
                        "run_id": run_dir.name,
                        "timestamp": run_dir.stat().st_mtime,
                        "authorization": report.get("authorization", "unknown"),
                        "findings_count": len(report.get("findings", [])),
                    })
                except Exception:
                    pass
        
        return runs


# Global scan manager
scan_manager = ScanManager()


class SentinelHandler(SimpleHTTPRequestHandler):
    """HTTP handler for the Sentinel web UI."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory="ui", **kwargs)
    
    def do_GET(self):
        parsed = urlparse(self.path)
        
        if parsed.path == "/":
            self.serve_file("firmware_run.html", "text/html")
        elif parsed.path == "/api/runs":
            self.send_json(scan_manager.get_runs())
        elif parsed.path == "/api/active":
            self.send_json(scan_manager.active_scans)
        elif parsed.path == "/sse":
            self.handle_sse()
        elif parsed.path.startswith("/runs/"):
            # Serve report files
            file_path = Path(parsed.path.lstrip("/"))
            if file_path.exists() and file_path.is_file():
                self.send_json(json.loads(file_path.read_text()))
            else:
                self.send_error(404)
        else:
            super().do_GET()
    
    def do_POST(self):
        parsed = urlparse(self.path)
        
        if parsed.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            data = json.loads(body)
            
            image_path = data.get("image_path")
            scope_ref = data.get("scope_ref", "LOCAL-TEST")
            firmware_sha256 = data.get("firmware_sha256")
            
            if not image_path or not Path(image_path).exists():
                self.send_json({"error": "Invalid image path"}, status=400)
                return
            
            run_id = scan_manager.start_scan(image_path, scope_ref, firmware_sha256)
            self.send_json({"run_id": run_id, "status": "started"})
        else:
            self.send_error(404)
    
    def handle_sse(self):
        """Server-Sent Events endpoint for live updates."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        
        q = scan_manager.subscribe()
        try:
            while True:
                try:
                    event = q.get(timeout=30)
                    self.wfile.write(f"data: {event}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Send keepalive
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            scan_manager.unsubscribe(q)
    
    def serve_file(self, filename: str, content_type: str):
        """Serve a file from the ui directory."""
        file_path = Path("ui") / filename
        if file_path.exists():
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            self.wfile.write(file_path.read_bytes())
        else:
            self.send_error(404)
    
    def send_json(self, data: Any, status: int = 200):
        """Send a JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2).encode())
    
    def log_message(self, format, *args):
        """Suppress default logging."""
        pass


def run_server(host: str = "127.0.0.1", port: int = 8089):
    """Start the web server."""
    server = HTTPServer((host, port), SentinelHandler)
    print(f"Sentinel UI running at http://{host}:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
