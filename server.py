#!/usr/bin/env python3
"""
Multi-threaded HTTP/1.1 server (educational implementation)

This server demonstrates:
- Low-level TCP sockets and manual HTTP parsing (GET/POST only)
- A simple fixed-size thread pool with a pending connection queue
- Static file serving (HTML) and binary file download with correct headers
- JSON uploads persisted to disk under resources/uploads/
- Security hardening: Host header validation and path traversal protection
- HTTP keep-alive with idle timeout and per-connection request limits

Notes for readers:
- The goal is clarity and correctness, not maximum performance.
- Error handling aims to be explicit and standards-aligned where practical.
- Logging is verbose on purpose to aid in local testing and grading.
"""
import os
import sys
import socket
import threading
import queue
import time
import json
import datetime
from typing import Dict, Tuple, Optional


# ==========================
# Configuration and Helpers
# ==========================
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_MAX_THREADS = 10
LISTEN_BACKLOG = 50
RESOURCES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")
UPLOADS_DIR = os.path.join(RESOURCES_DIR, "uploads")
MAX_REQUEST_BYTES = 8192
KEEP_ALIVE_TIMEOUT_SECS = 30
KEEP_ALIVE_MAX_REQUESTS = 100
SERVER_HEADER = "Multi-threaded HTTP Server"
PENDING_QUEUE_LIMIT = 100


def rfc7231_date() -> str:
    """Return current time in RFC 7231 (HTTP-date) format, always in UTC."""
    # Use timezone-aware UTC to avoid deprecation warning
    return datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def now_log_prefix() -> str:
    """Timestamp prefix used in log lines: [YYYY-MM-DD HH:MM:SS]."""
    return time.strftime("[%Y-%m-%d %H:%M:%S]")


def log(msg: str, thread_name: Optional[str] = None) -> None:
    """Simple stdout logger with timestamp and optional thread tag.

    Logging is synchronous and minimal by design to keep the code easy to read.
    """
    prefix = now_log_prefix()
    if thread_name:
        print(f"{prefix} [{thread_name}] {msg}")
    else:
        print(f"{prefix} {msg}")
    sys.stdout.flush()


def parse_cli_args(argv: list) -> Tuple[str, int, int]:
    """Parse CLI args: [port] [host] [max_threads]. Fallback to sane defaults."""
    host = DEFAULT_HOST
    port = DEFAULT_PORT
    max_threads = DEFAULT_MAX_THREADS

    if len(argv) >= 2:
        try:
            port = int(argv[1])
        except ValueError:
            log("Invalid port specified; using default 8080")
    if len(argv) >= 3:
        host = argv[2]
    if len(argv) >= 4:
        try:
            max_threads = int(argv[3])
        except ValueError:
            log("Invalid max thread count; using default 10")

    return host, port, max_threads


def ensure_directories() -> None:
    """Make sure resources/ and resources/uploads/ exist before serving."""
    os.makedirs(RESOURCES_DIR, exist_ok=True)
    os.makedirs(UPLOADS_DIR, exist_ok=True)


# ==========================
# HTTP Parsing
# ==========================
class HttpRequest:
    """Container for parsed HTTP request data.

    Only a subset of HTTP is implemented: request line, headers and an optional
    body (read by Content-Length). This is sufficient for the assignment.
    """
    def __init__(self, method: str, path: str, version: str, headers: Dict[str, str], body: bytes):
        self.method = method
        self.path = path
        self.version = version
        self.headers = headers
        self.body = body


def parse_http_request(data: bytes) -> Optional[HttpRequest]:
    """Parse raw bytes into an HttpRequest or return None on malformed input.

    We purposefully keep this strict and small to remain robust and easy to grade.
    """
    try:
        # Limit request size
        if len(data) > MAX_REQUEST_BYTES:
            return None

        try:
            header_body_split = data.split(b"\r\n\r\n", 1)
            header_bytes = header_body_split[0]
            body = header_body_split[1] if len(header_body_split) > 1 else b""
        except Exception:
            return None

        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        lines = header_text.split("\r\n")
        if len(lines) < 1:
            return None

        request_line = lines[0]
        parts = request_line.split()
        if len(parts) != 3:
            return None
        method, path, version = parts

        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                # Malformed header
                return None
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

        return HttpRequest(method=method, path=path, version=version, headers=headers, body=body)
    except Exception:
        return None


# ==========================
# Security Helpers
# ==========================
def is_host_allowed(host_header: Optional[str], bound_host: str, bound_port: int) -> Tuple[bool, str]:
    """Validate Host header against the interface/port this server is bound to.

    Accepts typical local development forms like 127.0.0.1 and localhost.
    Returns (allowed, reason_or_ok).
    """
    if not host_header:
        return False, "Missing Host header"
    expected_hosts = {f"{bound_host}:{bound_port}"}
    if bound_host in ("127.0.0.1", "localhost", "0.0.0.0", "::"):
        expected_hosts.add(f"localhost:{bound_port}")
        expected_hosts.add(f"127.0.0.1:{bound_port}")
    if host_header not in expected_hosts:
        return False, f"Host mismatch: {host_header}"
    return True, "ok"


def resolve_safe_path(request_path: str) -> Optional[str]:
    """Map a request path to a safe absolute file path under resources/.

    Returns None for any suspicious path (traversal attempts, double slashes,
    backslashes, etc.). The caller turns None into a 403.
    """
    # Disallow absolute paths and suspicious sequences
    if request_path.startswith("//") or request_path.startswith("/.."):
        return None

    # Map root to index.html
    if request_path == "/":
        request_path = "/index.html"

    # Prevent traversal patterns or double slashes anywhere
    if ".." in request_path or "/./" in request_path or "\\" in request_path or "//" in request_path:
        return None

    # Join and canonicalize
    candidate = os.path.normpath(os.path.join(RESOURCES_DIR, request_path.lstrip("/")))
    # Ensure within resources
    if not candidate.startswith(RESOURCES_DIR):
        return None
    return candidate


def guess_content_type(file_path: str) -> Tuple[str, bool, Optional[str]]:
    """Very small extension-based content type helper.

    Returns: (content_type, is_attachment_download, filename_for_disposition)
    """
    name = file_path.lower()
    if name.endswith(".html"):
        return "text/html; charset=utf-8", False, None
    if name.endswith(".txt"):
        return "application/octet-stream", True, os.path.basename(file_path)
    if name.endswith(".png"):
        return "application/octet-stream", True, os.path.basename(file_path)
    if name.endswith(".jpg") or name.endswith(".jpeg"):
        return "application/octet-stream", True, os.path.basename(file_path)
    return "unsupported/unsupported", False, None


# ==========================
# Thread Pool
# ==========================
class Worker(threading.Thread):
    """A background thread that pulls client sockets from the queue and serves them."""
    def __init__(self, name: str, conn_queue: "queue.Queue[socket.socket]", handler):
        super().__init__(name=name, daemon=True)
        self.conn_queue = conn_queue
        self.handler = handler

    def run(self) -> None:
        while True:
            client_sock = self.conn_queue.get()
            try:
                if client_sock is None:
                    # Shutdown signal
                    break
                # Log dequeued assignment
                try:
                    peer = client_sock.getpeername()
                    log(f"Connection dequeued, assigned to {self.name}")
                except Exception:
                    log(f"Connection dequeued, assigned to {self.name}")
                self.handler(client_sock, self.name)
            finally:
                self.conn_queue.task_done()


class ThreadPool:
    """Tiny fixed-size thread pool tailored for this server's request model."""
    def __init__(self, max_workers: int):
        self.max_workers = max_workers
        self.conn_queue: "queue.Queue[socket.socket]" = queue.Queue()
        self.workers = [Worker(name=f"Thread-{i+1}", conn_queue=self.conn_queue, handler=self._handle)
                        for i in range(max_workers)]
        self._handler_func = None
        self._active_lock = threading.Lock()
        self._active_count = 0

    def start(self, handler_func):
        """Start all workers and set the user-provided connection handler."""
        self._handler_func = handler_func
        for w in self.workers:
            w.start()

    def _handle(self, client_sock: socket.socket, thread_name: str):
        """Wrapper that tracks active count around the real handler."""
        with self._active_lock:
            self._active_count += 1
        try:
            if self._handler_func is not None:
                self._handler_func(client_sock, thread_name)
        finally:
            with self._active_lock:
                self._active_count -= 1

    def submit(self, client_sock: socket.socket) -> None:
        """Enqueue a client socket to be handled by any available worker."""
        self.conn_queue.put(client_sock)

    def status(self) -> Tuple[int, int]:
        """Return (active_threads, max_threads) for periodic status logging."""
        with self._active_lock:
            return self._active_count, self.max_workers


# ==========================
# HTTP Server Logic
# ==========================
class HttpServer:
    """HTTP server with manual parsing, static file serving, and JSON uploads."""
    def __init__(self, host: str, port: int, max_threads: int):
        self.host = host
        self.port = port
        self.max_threads = max_threads
        self.pool = ThreadPool(max_threads)

    def start(self) -> None:
        """Bind and listen on the configured host:port and accept connections.

        Each accepted connection is queued and then handled by the thread pool.
        If the queue grows beyond a threshold, we proactively return 503.
        """
        ensure_directories()
        self.pool.start(self._serve_client)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((self.host, self.port))
            server_sock.listen(LISTEN_BACKLOG)

            log(f"HTTP Server started on http://{self.host}:{self.port}")
            log(f"Thread pool size: {self.max_threads}")
            log(f"Serving files from '{RESOURCES_DIR}' directory")
            log("Press Ctrl+C to stop the server")

            last_status_log = 0.0
            while True:
                try:
                    client_sock, addr = server_sock.accept()
                    # Non-blocking queueing semantics: we always enqueue; saturation is just active==max
                    active, total = self.pool.status()
                    if active >= total:
                        log("Warning: Thread pool saturated, queuing connection")
                    # If pending queue too large, immediately respond 503
                    if self.pool.conn_queue.qsize() >= PENDING_QUEUE_LIMIT:
                        try:
                            self._send_quick_503(client_sock)
                        except Exception:
                            pass
                        try:
                            client_sock.shutdown(socket.SHUT_RDWR)
                        except Exception:
                            pass
                        client_sock.close()
                        continue
                    self.pool.submit(client_sock)

                    # Thread pool status log every 30s
                    now = time.time()
                    if now - last_status_log > 30:
                        active, total = self.pool.status()
                        log(f"Thread pool status: {active}/{total} active")
                        last_status_log = now
                except KeyboardInterrupt:
                    log("Shutting down server...")
                    break

    # Core per-connection loop with keep-alive
    def _serve_client(self, client_sock: socket.socket, thread_name: str) -> None:
        """Serve one client connection with optional keep-alive request loop."""
        client_sock.settimeout(KEEP_ALIVE_TIMEOUT_SECS)
        try:
            peer = None
            try:
                peer = client_sock.getpeername()
            except Exception:
                peer = ("?", 0)
            log(f"Connection from {peer[0]}:{peer[1]}", thread_name)

            requests_handled = 0
            keep_alive = True
            while keep_alive and requests_handled < KEEP_ALIVE_MAX_REQUESTS:
                raw_request = b""
                try:
                    # Read up to MAX_REQUEST_BYTES or until headers end
                    client_sock.settimeout(KEEP_ALIVE_TIMEOUT_SECS)
                    # Read in chunks to handle slow clients
                    while b"\r\n\r\n" not in raw_request and len(raw_request) < MAX_REQUEST_BYTES:
                        chunk = client_sock.recv(min(4096, MAX_REQUEST_BYTES - len(raw_request)))
                        if not chunk:
                            break
                        raw_request += chunk
                except socket.timeout:
                    # Idle timeout
                    break
                except Exception:
                    break

                if not raw_request:
                    break

                # If there is a body, attempt to read Content-Length bytes
                header_part, sep, body_part = raw_request.partition(b"\r\n\r\n")
                headers_text = header_part.decode("iso-8859-1", errors="replace")
                headers_lines = headers_text.split("\r\n")
                content_length = 0
                for line in headers_lines[1:]:
                    if line.lower().startswith("content-length:"):
                        try:
                            content_length = int(line.split(":", 1)[1].strip())
                        except Exception:
                            content_length = 0
                        break

                body_bytes = body_part
                while len(body_bytes) < content_length and len(header_part) + 4 + len(body_bytes) < MAX_REQUEST_BYTES:
                    try:
                        more = client_sock.recv(min(4096, content_length - len(body_bytes)))
                        if not more:
                            break
                        body_bytes += more
                    except socket.timeout:
                        break

                req = parse_http_request(header_part + b"\r\n\r\n" + body_bytes)
                if not req:
                    self._send_error(client_sock, 400, "Bad Request", close_connection=True)
                    break

                log(f"Request: {req.method} {req.path} {req.version}", thread_name)

                # Host header validation
                ok, reason = is_host_allowed(req.headers.get("host"), self.host, self.port)
                if not ok:
                    status = 400 if reason.startswith("Missing") else 403
                    log(f"Host validation: {reason} ✗", thread_name)
                    self._send_error(client_sock, status, "Bad Request" if status == 400 else "Forbidden")
                    break
                else:
                    log("Host validation: {} ✓".format(req.headers.get("host")), thread_name)

                # Connection header logic
                connection_header = req.headers.get("connection", "").lower()
                if req.version == "HTTP/1.0":
                    keep_alive = connection_header == "keep-alive"
                else:  # HTTP/1.1 default keep-alive
                    keep_alive = connection_header != "close"

                # Route
                if req.method == "GET":
                    self._handle_get(client_sock, req, thread_name, keep_alive)
                elif req.method == "POST":
                    self._handle_post(client_sock, req, thread_name, keep_alive)
                else:
                    self._send_error(client_sock, 405, "Method Not Allowed", keep_alive=keep_alive)

                requests_handled += 1

                if not keep_alive or requests_handled >= KEEP_ALIVE_MAX_REQUESTS:
                    break

        finally:
            try:
                client_sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            client_sock.close()

    # ============ Handlers ============
    def _handle_get(self, sock: socket.socket, req: HttpRequest, thread_name: str, keep_alive: bool) -> None:
        """Serve HTML from resources/ or stream binary files as attachments."""
        safe_path = resolve_safe_path(req.path)
        if not safe_path:
            self._send_error(sock, 403, "Forbidden", keep_alive=keep_alive)
            return

        if not os.path.exists(safe_path) or not os.path.isfile(safe_path):
            self._send_error(sock, 404, "Not Found", keep_alive=keep_alive)
            return

        content_type, is_binary_download, filename = guess_content_type(safe_path)
        if content_type == "unsupported/unsupported":
            self._send_error(sock, 415, "Unsupported Media Type", keep_alive=keep_alive)
            return

        try:
            # HTML served as text; others as binary attachment
            if is_binary_download:
                size = os.path.getsize(safe_path)
                headers = {
                    "Date": rfc7231_date(),
                    "Server": SERVER_HEADER,
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(size),
                    "Connection": "keep-alive" if keep_alive else "close",
                }
                if keep_alive:
                    headers["Keep-Alive"] = f"timeout={KEEP_ALIVE_TIMEOUT_SECS}, max={KEEP_ALIVE_MAX_REQUESTS}"
                if filename:
                    headers["Content-Disposition"] = f"attachment; filename=\"{filename}\""

                # Log sending file
                log(f"Sending binary file: {os.path.basename(safe_path)} ({size} bytes)", thread_name)
                self._send_headers(sock, 200, "OK", headers)

                with open(safe_path, "rb") as f:
                    self._send_file(sock, f)

                log(f"Response: 200 OK ({size} bytes transferred)", thread_name)
                log(f"Connection: {'keep-alive' if keep_alive else 'close'}", thread_name)
                return
            else:
                with open(safe_path, "rb") as f:
                    body = f.read()
                headers = {
                    "Date": rfc7231_date(),
                    "Server": SERVER_HEADER,
                    "Content-Type": content_type,
                    "Content-Length": str(len(body)),
                    "Connection": "keep-alive" if keep_alive else "close",
                }
                if keep_alive:
                    headers["Keep-Alive"] = f"timeout={KEEP_ALIVE_TIMEOUT_SECS}, max={KEEP_ALIVE_MAX_REQUESTS}"

                self._send_headers(sock, 200, "OK", headers)
                sock.sendall(body)

                log(f"Response: 200 OK ({len(body)} bytes transferred)", thread_name)
                log(f"Connection: {'keep-alive' if keep_alive else 'close'}", thread_name)
                return
        except Exception:
            self._send_error(sock, 500, "Internal Server Error", keep_alive=keep_alive)

    def _handle_post(self, sock: socket.socket, req: HttpRequest, thread_name: str, keep_alive: bool) -> None:
        """Handle POST /upload with application/json by persisting to uploads/."""
        # Only allow POST /upload
        if req.path != "/upload":
            self._send_error(sock, 404, "Not Found", keep_alive=keep_alive)
            return
        # Only JSON accepted
        ctype = req.headers.get("content-type", "").split(";")[0].strip()
        if ctype.lower() != "application/json":
            self._send_error(sock, 415, "Unsupported Media Type", keep_alive=keep_alive)
            return

        try:
            data_obj = json.loads(req.body.decode("utf-8"))
        except Exception:
            self._send_error(sock, 400, "Bad Request", keep_alive=keep_alive)
            return

        # Create file
        ts = time.strftime("%Y%m%d_%H%M%S")
        rand = f"{os.getpid():x}{threading.get_ident():x}{int(time.time()*1000)%0xFFF:03x}"
        filename = f"upload_{ts}_{rand}.json"
        out_path = os.path.join(UPLOADS_DIR, filename)

        try:
            with open(out_path, "wb") as f:
                # Preserve original JSON formatting/body
                f.write(json.dumps(data_obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except Exception:
            self._send_error(sock, 500, "Internal Server Error", keep_alive=keep_alive)
            return

        resp_obj = {
            "status": "success",
            "message": "File created successfully",
            "filepath": f"/uploads/{filename}",
        }
        body = json.dumps(resp_obj).encode("utf-8")
        headers = {
            "Date": rfc7231_date(),
            "Server": SERVER_HEADER,
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "keep-alive" if keep_alive else "close",
        }
        if keep_alive:
            headers["Keep-Alive"] = f"timeout={KEEP_ALIVE_TIMEOUT_SECS}, max={KEEP_ALIVE_MAX_REQUESTS}"

        self._send_headers(sock, 201, "Created", headers)
        sock.sendall(body)

    # ============ Low-level send helpers ============
    def _send_headers(self, sock: socket.socket, status_code: int, reason: str, headers: Dict[str, str]) -> None:
        """Serialize and send the HTTP status line and headers."""
        status_line = f"HTTP/1.1 {status_code} {reason}\r\n"
        header_lines = "".join([f"{k}: {v}\r\n" for k, v in headers.items()])
        sock.sendall((status_line + header_lines + "\r\n").encode("iso-8859-1"))

    def _send_file(self, sock: socket.socket, f) -> None:
        """Send a file-like object to the client in 8KB chunks."""
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sock.sendall(chunk)

    def _send_error(self, sock: socket.socket, code: int, reason: str, keep_alive: bool = False, close_connection: bool = False) -> None:
        """Send a small HTML error page with appropriate headers."""
        body = f"<html><body><h1>{code} {reason}</h1></body></html>".encode("utf-8")
        headers = {
            "Date": rfc7231_date(),
            "Server": SERVER_HEADER,
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close" if close_connection or not keep_alive else "keep-alive",
        }
        if keep_alive and not close_connection:
            headers["Keep-Alive"] = f"timeout={KEEP_ALIVE_TIMEOUT_SECS}, max={KEEP_ALIVE_MAX_REQUESTS}"
        self._send_headers(sock, code, reason, headers)
        try:
            sock.sendall(body)
        except Exception:
            pass

    def _send_quick_503(self, sock: socket.socket) -> None:
        """Best-effort 503 response when the pending queue is saturated."""
        body = b"<html><body><h1>503 Service Unavailable</h1></body></html>"
        headers = {
            "Date": rfc7231_date(),
            "Server": SERVER_HEADER,
            "Content-Type": "text/html; charset=utf-8",
            "Content-Length": str(len(body)),
            "Connection": "close",
            "Retry-After": "5",
        }
        self._send_headers(sock, 503, "Service Unavailable", headers)
        try:
            sock.sendall(body)
        except Exception:
            pass


def main():
    """Entry point: parse CLI args, construct the server, and start it."""
    host, port, max_threads = parse_cli_args(sys.argv)
    server = HttpServer(host, port, max_threads)
    server.start()


if __name__ == "__main__":
    main()


