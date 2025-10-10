Multi-threaded HTTP Server
==========================

This repository contains a compact, readable, and fully working multi-threaded HTTP/1.1 server built with raw sockets in Python. It is designed to be easy to understand and grade, while still covering the critical parts of HTTP, concurrency, and web security.

Overview
--------
This is a multi-threaded HTTP/1.1 server implemented in Python. It serves HTML files and provides binary downloads for PNG/JPEG/TXT, and handles JSON uploads via POST. It includes a bounded thread pool with a queue, security hardening (path traversal protection and Host header validation), and HTTP keep-alive with idle timeout.

What’s included:
- `server.py`: the full server with clear comments and docstrings.
- `resources/`: static files (HTML, images, text) and `uploads/` for POSTed JSON.

Run Instructions
----------------
- Requirements: Python 3.9+
- Default host/port: 127.0.0.1:8080

Commands:

```bash
python3 server.py               # defaults to host=127.0.0.1, port=8080, threads=10
python3 server.py 8000          # host=127.0.0.1, port=8000
python3 server.py 8000 0.0.0.0  # host=0.0.0.0, port=8000
python3 server.py 8000 0.0.0.0 20  # host=0.0.0.0, port=8000, threads=20
```

Resources Directory
-------------------
- Served root: `resources/`
- Default document: `/` → `resources/index.html`
- Uploads directory: `resources/uploads/`

Tip: keep all test assets inside `resources/`. The server only serves from this folder and will reject any path that attempts to escape it.

HTTP Features
-------------
- Methods: GET, POST
  - GET:
    - `*.html` served as `text/html; charset=utf-8`
    - `*.png`, `*.jpg`/`*.jpeg`, `*.txt` served as `application/octet-stream` with `Content-Disposition: attachment`
  - POST:
    - Only `POST /upload` with `Content-Type: application/json`
    - Creates `resources/uploads/upload_YYYYMMDD_HHMMSS_<id>.json`
    - Responds 201 with JSON body containing `filepath`
- Unsupported methods: 405
- Unsupported media types/file extensions: 415
- Not found: 404
- Server errors: 500
- Saturation: 503 with `Retry-After: 5` when queue is full

Description of Binary Transfer Implementation
--------------------------------------------
For binary files (`.png`, `.jpg`/`.jpeg`, `.txt`), the server:
- Opens files in binary mode to preserve exact bytes.
- Sends headers with `Content-Type: application/octet-stream`, precise `Content-Length`, and `Content-Disposition: attachment; filename="..."` so browsers download the file.
- Streams data in 8KB chunks for efficiency without excessive memory use.

HTML (`.html`) is returned with `text/html; charset=utf-8` so browsers render the page.

Security
--------
- Path traversal protection: rejects paths with `..`, `/./`, `\\`, absolute paths, and double-slash roots
- Host header validation: only accepts `localhost:<port>` and `127.0.0.1:<port>` (or bound host) 
- Logs all security violations

Security Measures Implemented (Why it matters)
----------------------------------------------
- Host header validation prevents simple host-spoofing during local testing and makes routing expectations explicit.
- Path traversal defense canonicalizes the filesystem path and rejects suspicious sequences before any file access.
- Missing `Host` header (required by HTTP/1.1) yields `400 Bad Request`.

Concurrency & Thread Pool
-------------------------
- Configurable thread pool size (default 10)
- Pending connection queue with limit (default 100)
- Logs when saturated and when connections are dequeued and assigned to a worker

Thread Pool Architecture Explanation
------------------------------------
- The main thread accepts TCP connections and enqueues them.
- A fixed number of worker threads pull connections from the queue and process requests.
- If workers are all busy, new connections wait in the queue. If the queue grows too large, the server sends a `503 Service Unavailable` with a `Retry-After` hint to relieve pressure.

Keep-Alive & Timeouts
---------------------
- HTTP/1.1 default keep-alive; HTTP/1.0 default close
- `Keep-Alive: timeout=30, max=100`
- Idle connections close after 30s; max 100 requests per connection

This balances performance (fewer TCP handshakes) with resource safety (idle connections are cleaned up).

Testing Quickstart
------------------
In a separate terminal, after starting the server:

```bash
# HTML
curl -i http://127.0.0.1:8080/
curl -i http://127.0.0.1:8080/about.html

# Binary downloads
curl -i http://127.0.0.1:8080/logo.png -o /dev/null -s -D -
curl -i http://127.0.0.1:8080/photo.jpg -o /dev/null -s -D -
curl -i http://127.0.0.1:8080/sample.txt -o /dev/null -s -D -

# POST upload
curl -i -X POST http://127.0.0.1:8080/upload -H 'Content-Type: application/json' --data '{"hello":"world"}'

# Errors
curl -i -X PUT http://127.0.0.1:8080/index.html     # 405
curl -i http://127.0.0.1:8080/does-not-exist.png     # 404
curl -i 'http://127.0.0.1:8080/../etc/passwd'        # 403
curl -i -H 'Host: evil.com:8080' http://127.0.0.1:8080/  # 403
```

Notes on "Server Stopped" Perception
------------------------------------
- The server continues running until you press Ctrl+C.
- Individual client connections may close when:
  - 30s idle timeout is reached
  - `Connection: close` is requested
  - Host or path validation fails (400/403)
- These are expected and logged; the server itself remains active.

Architecture Summary
--------------------
- `server.py`
  - CLI arg parsing (host, port, threads)
  - `ThreadPool` with workers and a pending queue
  - HTTP parsing (request line, headers, body up to 8192 bytes)
  - Security checks (Host validation, safe path resolution)
  - GET handlers for HTML/binary with proper headers
  - POST `/upload` JSON handler
  - Keep-Alive and idle timeout handling
  - Structured logging with timestamps and thread names

To browse the flow quickly: start at `HttpServer.start()` (accept loop), then check `ThreadPool`, and finally the GET/POST handlers.

How the code works (high level)
------------------------------
- The main entrypoint `main()` constructs `HttpServer(host, port, max_threads)` and calls `start()`.
- The accept loop in `HttpServer.start()` creates a TCP listening socket, accepts connections, and enqueues each client socket into a small `ThreadPool` (with a bounded pending queue and periodic status logging). If the queue is over the safety limit, the server immediately returns `503 Service Unavailable`.
- Worker threads (`Worker` inside the `ThreadPool`) call back into `HttpServer._serve_client`, which:
  - reads request bytes with a timeout (30s) and a hard request cap (8192 bytes),
  - parses the start-line, headers, and optional body via `parse_http_request`,
  - validates the `Host` header with `is_host_allowed` and the URL path with `resolve_safe_path` to prevent traversal,
  - routes by method: `GET` → `_handle_get`, `POST` → `_handle_post`, otherwise `405`.
- GET handling (`_handle_get`):
  - `.html` files are returned inline with `Content-Type: text/html; charset=utf-8`.
  - `.png`, `.jpg/.jpeg`, `.txt` are returned as downloads using `Content-Type: application/octet-stream` and `Content-Disposition: attachment; filename="..."`.
  - Large binaries are streamed in 8KB chunks after headers, keeping memory usage low and transfers efficient.
- POST `/upload` (`_handle_post`): enforces `Content-Type: application/json`, parses JSON, writes it into `resources/uploads/upload_YYYYMMDD_HHMMSS_<id>.json`, and replies `201 Created` with a JSON body containing the virtual path.
- Connection policy: default HTTP/1.1 keep‑alive (closes on HTTP/1.0 unless `Connection: keep-alive`, and on explicit `Connection: close`). Responses include `Keep-Alive: timeout=30, max=100`. Idle connections close after 30s; per-connection max is 100 requests.
- Errors: malformed requests → `400`; forbidden paths/Host mismatch → `403`; missing files → `404`; unsupported methods → `405`; wrong media type → `415`; unexpected issues → `500`; saturated queue → `503` with `Retry-After`.

Known Limitations
-----------------
- Minimal MIME type handling by extension only
- No chunked transfer encoding support
- No TLS support (HTTP only)

These are intentional trade-offs to keep the code concise and focused on the assignment’s learning goals.

Repository
----------
Push this folder to your own GitHub repository and share the link. Suggested commands:

```bash
git init
git add .
git commit -m "Multi-threaded HTTP server"
git branch -M main
# git remote add origin <YOUR_GITHUB_REPO_URL>
# git push -u origin main
```


