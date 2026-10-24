#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from concurrent.futures import ThreadPoolExecutor
from http.client import BadStatusLine, CannotSendRequest, HTTPConnection, HTTPSConnection, RemoteDisconnected
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import queue
import re
import ssl
import threading
import time
from urllib.parse import urlsplit

UPSTREAM = os.environ.get("QODER_UPSTREAM", "http://127.0.0.1:8790").rstrip("/")
LISTEN_HOST = os.environ.get("QODER_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("QODER_PORT", 8791))
LISTEN = (LISTEN_HOST, LISTEN_PORT)

API_KEY_FILE = os.environ.get("QODER_API_KEY_FILE", "/opt/qoder2api/.apikey")
CONFIG_FILE = os.environ.get("QODER_CONFIG_FILE", "/opt/qoder2api/blocked-models.json")
KEYS_FILE = os.environ.get("QODER_KEYS_FILE", "/opt/qoder2api/admin/keys.json")
KEY_CHECK = os.environ.get("QODER_KEY_CHECK", "1").strip().lower() not in ("0", "false", "no", "off")

UPSTREAM_TIMEOUT = 1800.0
MAX_BODY_BYTES = 64 * 1024 * 1024
ALIAS_TTL = 60
FAST_MODEL_PARSE_LIMIT = 65536
_MODEL_BYTES_RE = re.compile(rb'"model"\s*:\s*"([^"\\]{1,256})"')

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade",
}

_ALIAS_CACHE = {"at": 0.0, "map": {}}
_ALIAS_LOCK = threading.Lock()
_FILE_CACHE_LOCK = threading.Lock()
_API_KEY_CACHE = {"path": None, "mtime_ns": None, "size": None, "raw": None, "val": ""}
_CONFIG_CACHE = {"path": None, "mtime_ns": None, "size": None, "raw": None, "block": set(), "ctx": None}
_KEYS_CACHE = {"path": None, "mtime_ns": None, "size": None, "raw": None, "keys": frozenset()}
_SSL_CTX = None


class _UpstreamPool:
    def __init__(self, max_per_host=16, idle_timeout=55.0):
        self._max_per_host = max_per_host
        self._idle_timeout = idle_timeout
        self._pools = {}
        self._lock = threading.Lock()

    def _bucket(self, key):
        with self._lock:
            q = self._pools.get(key)
            if q is None:
                q = queue.LifoQueue(maxsize=self._max_per_host)
                self._pools[key] = q
            return q

    def _new_conn(self, scheme, host, port, timeout):
        global _SSL_CTX
        if scheme == "https":
            if _SSL_CTX is None:
                _SSL_CTX = ssl.create_default_context()
            return HTTPSConnection(host, port, timeout=timeout, context=_SSL_CTX)
        return HTTPConnection(host, port, timeout=timeout)

    def request(self, method, base_url, path, body=None, headers=None, timeout=1800.0):
        parts = urlsplit(base_url)
        scheme = (parts.scheme or "http").lower()
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if scheme == "https" else 80)
        base_path = parts.path.rstrip("/")
        target = (base_path + path) if base_path else path
        key = (scheme, host, port, float(timeout))
        bucket = self._bucket(key)
        now = time.monotonic()

        while True:
            try:
                ts, conn = bucket.get_nowait()
            except queue.Empty:
                conn = None
                break
            if now - ts > self._idle_timeout or getattr(conn, "sock", None) is None:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            break

        reused = conn is not None
        if conn is None:
            conn = self._new_conn(scheme, host, port, timeout)

        try:
            conn.request(method, target, body=body, headers=headers or {})
            resp = conn.getresponse()
            return conn, resp, bucket
        except (RemoteDisconnected, CannotSendRequest, BadStatusLine, ConnectionError, OSError):
            try:
                conn.close()
            except Exception:
                pass
            if not reused:
                raise
            conn = self._new_conn(scheme, host, port, timeout)
            conn.request(method, target, body=body, headers=headers or {})
            resp = conn.getresponse()
            return conn, resp, bucket

    @staticmethod
    def release(conn, resp, bucket):
        try:
            if resp is not None and not getattr(resp, "will_close", True) and resp.isclosed():
                try:
                    bucket.put_nowait((time.monotonic(), conn))
                    return
                except queue.Full:
                    pass
        except Exception:
            pass
        try:
            conn.close()
        except Exception:
            pass


_UPSTREAM_POOL = _UpstreamPool()


def _api_key(path=None):
    target = path or API_KEY_FILE
    try:
        st = os.stat(target)
        with open(target, "rb") as f:
            raw = f.read()
    except Exception:
        return ""
    with _FILE_CACHE_LOCK:
        if (_API_KEY_CACHE["path"] == target and
                _API_KEY_CACHE["mtime_ns"] == st.st_mtime_ns and
                _API_KEY_CACHE["size"] == st.st_size and
                _API_KEY_CACHE["raw"] == raw):
            return _API_KEY_CACHE["val"]
        val = raw.decode("utf-8", "ignore").strip()
        _API_KEY_CACHE["path"] = target
        _API_KEY_CACHE["mtime_ns"] = st.st_mtime_ns
        _API_KEY_CACHE["size"] = st.st_size
        _API_KEY_CACHE["raw"] = raw
        _API_KEY_CACHE["val"] = val
        return val


def _config(path=None):
    target = path or CONFIG_FILE
    try:
        st = os.stat(target)
        with open(target, "rb") as f:
            raw = f.read()
    except Exception:
        return set(), None
    with _FILE_CACHE_LOCK:
        if (_CONFIG_CACHE["path"] == target and
                _CONFIG_CACHE["mtime_ns"] == st.st_mtime_ns and
                _CONFIG_CACHE["size"] == st.st_size and
                _CONFIG_CACHE["raw"] == raw):
            return set(_CONFIG_CACHE["block"]), _CONFIG_CACHE["ctx"]
    try:
        d = json.loads(raw.decode("utf-8"))
    except Exception:
        return set(), None
    if isinstance(d, list):
        ids = {str(x).strip().lower() for x in d if str(x).strip()}
        ctx = None
    elif isinstance(d, dict):
        ids = {str(x).strip().lower() for x in (d.get("models") or []) if str(x).strip()}
        ctx = d.get("context_length")
        try:
            ctx = int(ctx) if ctx else None
        except (TypeError, ValueError):
            ctx = None
    else:
        return set(), None
    with _FILE_CACHE_LOCK:
        _CONFIG_CACHE["path"] = target
        _CONFIG_CACHE["mtime_ns"] = st.st_mtime_ns
        _CONFIG_CACHE["size"] = st.st_size
        _CONFIG_CACHE["raw"] = raw
        _CONFIG_CACHE["block"] = set(ids)
        _CONFIG_CACHE["ctx"] = ctx
    return ids, ctx


def load_valid_keys(keys_path=None):
    target = keys_path or KEYS_FILE
    try:
        st = os.stat(target)
        with open(target, "rb") as f:
            raw = f.read()
    except Exception:
        return frozenset()

    with _FILE_CACHE_LOCK:
        if (_KEYS_CACHE["path"] == target and
                _KEYS_CACHE["mtime_ns"] == st.st_mtime_ns and
                _KEYS_CACHE["size"] == st.st_size and
                _KEYS_CACHE["raw"] == raw):
            return _KEYS_CACHE["keys"]

    valid = set()
    try:
        parsed = json.loads(raw.decode("utf-8", "ignore"))
        key_items = []
        if isinstance(parsed, dict):
            key_items = parsed.get("keys") or []
        elif isinstance(parsed, list):
            key_items = parsed

        for item in key_items:
            if isinstance(item, dict):
                k = str(item.get("key") or "").strip()
                enabled = item.get("enabled", True)
                if k and enabled is not False:
                    valid.add(k)
            elif isinstance(item, str):
                s = item.strip()
                if s:
                    valid.add(s)
    except Exception:
        valid = set()

    frozen = frozenset(valid)
    with _FILE_CACHE_LOCK:
        _KEYS_CACHE["path"] = target
        _KEYS_CACHE["mtime_ns"] = st.st_mtime_ns
        _KEYS_CACHE["size"] = st.st_size
        _KEYS_CACHE["raw"] = raw
        _KEYS_CACHE["keys"] = frozen
    return frozen


def _extract_model_fast(body):
    if not body:
        return ""
    if len(body) <= FAST_MODEL_PARSE_LIMIT:
        try:
            obj = json.loads(body.decode("utf-8", "ignore"))
        except Exception:
            obj = None
        if isinstance(obj, dict):
            return str(obj.get("model") or "").strip()
        return ""
    for window in (body[:16384], body[-16384:], body):
        m = _MODEL_BYTES_RE.search(window)
        if m:
            return m.group(1).decode("utf-8", "ignore").strip()
    return ""


def rewrite_models(payload, block, ctx):
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return payload
    keep = []
    for m in data:
        if not isinstance(m, dict):
            keep.append(m)
            continue
        if str(m.get("id") or "").strip().lower() in block:
            continue
        if ctx:
            for key in ("context_length", "max_input_tokens"):
                if key in m:
                    m[key] = ctx
        keep.append(m)
    payload["data"] = keep
    return payload


def _alias_map():
    """Fetch and cache upstream model alias map for 60 seconds."""
    now = time.time()
    with _ALIAS_LOCK:
        if now - _ALIAS_CACHE["at"] < ALIAS_TTL and _ALIAS_CACHE["map"]:
            return _ALIAS_CACHE["map"]

    amap = None
    conn = resp = bucket = None
    try:
        hdr = {"Connection": "keep-alive"}
        gw_key = _api_key()
        if gw_key:
            hdr["Authorization"] = "Bearer " + gw_key
        conn, resp, bucket = _UPSTREAM_POOL.request(
            "GET", UPSTREAM, "/v1/models",
            headers=hdr,
            timeout=30.0,
        )
        raw = resp.read(MAX_BODY_BYTES)
        resp.close()
        if resp.status == 200:
            data = json.loads(raw.decode("utf-8", "ignore"))
            parsed = {}
            for m in (data.get("data") or []):
                if not isinstance(m, dict):
                    continue
                mid = str(m.get("id") or "").strip().lower()
                if not mid:
                    continue
                names = {mid}
                for a in (m.get("aliases") or []):
                    names.add(str(a).strip().lower())
                parsed[mid] = names
            amap = parsed
    except Exception:
        amap = None
    finally:
        if conn is not None:
            _UPSTREAM_POOL.release(conn, resp, bucket)

    with _ALIAS_LOCK:
        if amap is None:
            amap = _ALIAS_CACHE["map"]
        _ALIAS_CACHE["map"] = amap
        _ALIAS_CACHE["at"] = time.time()
        return amap


def _is_blocked(model, block, aliases):
    m = str(model or "").strip().lower()
    if not m or not block:
        return False
    if m in block:
        return True
    for mid in block:
        if m in (aliases.get(mid) or ()):
            return True
    return False


def _safe_response_headers(headers):
    out = []
    for name, value in headers.items():
        if name.lower() in HOP_BY_HOP or name.lower() == "content-length":
            continue
        out.append((name, value))
    return out


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, max_workers=32):
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="qoder-filter")
        super().__init__(server_address, RequestHandlerClass)

    def process_request(self, request, client_address):
        try:
            self._executor.submit(self.process_request_thread, request, client_address)
        except Exception:
            self.handle_error(request, client_address)
            self.shutdown_request(request)

    def server_close(self):
        super().server_close()
        self._executor.shutdown(wait=False)


class FilterHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _send_json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def _extract_client_key(self):
        k = self.headers.get("X-Client-Key")
        if k:
            return k.strip()
        auth = self.headers.get("Authorization")
        if auth:
            s = auth.strip()
            if s.lower().startswith("bearer "):
                return s[7:].strip()
            return s
        return ""

    def _read_body(self):
        value = self.headers.get("Content-Length")
        try:
            length = int(value or 0)
        except ValueError:
            raise ValueError("invalid Content-Length")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError("request body is too large")
        return self.rfile.read(length) if length else None

    def _auth_401(self):
        self._send_json(401, {
            "error": {
                "message": "Incorrect API key provided or key disabled.",
                "type": "invalid_request_error",
                "param": None,
                "code": "invalid_api_key"
            }
        })

    def _blocked_404(self, model):
        self._send_json(404, {
            "error": {
                "code": "model_not_found",
                "message": "model is disabled on this gateway: " + str(model),
                "type": "api_error"
            }
        })

    def _forward(self):
        path_only = (self.path or "").split("?", 1)[0]
        if path_only == "/healthz":
            self._send_json(200, {"ok": True, "service": "qoder-model-filter"})
            return

        if KEY_CHECK:
            client_key = self._extract_client_key()
            valid_keys = load_valid_keys()
            if not client_key or client_key not in valid_keys:
                self._auth_401()
                return

        block, ctx = _config()
        body = self._read_body()

        if block and body:
            asked = _extract_model_fast(body)
            if asked and _is_blocked(asked, block, _alias_map()):
                self._blocked_404(asked)
                return

        headers = {}
        for name, value in self.headers.items():
            if name.lower() in HOP_BY_HOP or name.lower() in {"expect", "host", "content-length"}:
                continue
            headers[name] = value

        headers.setdefault("User-Agent", "QoderFilter/1.0")
        headers["Connection"] = "keep-alive"
        if body is not None:
            headers["Content-Length"] = str(len(body))

        gw_internal_key = _api_key()
        if gw_internal_key:
            headers["Authorization"] = "Bearer " + gw_internal_key

        upstream_path = self.path if self.path.startswith("/") else "/" + self.path

        try:
            conn, response, bucket = _UPSTREAM_POOL.request(
                self.command, UPSTREAM, upstream_path,
                body=body, headers=headers, timeout=UPSTREAM_TIMEOUT,
            )
        except (TimeoutError, OSError):
            self._send_json(502, {
                "error": {
                    "message": "Qoder upstream unreachable",
                    "type": "upstream_error"
                }
            })
            return

        if response.status >= 400:
            try:
                payload = response.read(MAX_BODY_BYTES + 1)
                if len(payload) <= MAX_BODY_BYTES:
                    response.close()
                self.send_response(response.status)
                for name, value in _safe_response_headers(response.headers):
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload[:MAX_BODY_BYTES])))
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                self.wfile.write(payload[:MAX_BODY_BYTES])
            finally:
                _UPSTREAM_POOL.release(conn, response, bucket)
            return

        # Rewrite models catalog
        if response.status == 200 and path_only.endswith("/models") and (block or ctx):
            try:
                raw = response.read(MAX_BODY_BYTES)
                response.close()
            finally:
                _UPSTREAM_POOL.release(conn, response, bucket)
            try:
                payload = json.loads(raw.decode("utf-8", "ignore"))
                raw = json.dumps(rewrite_models(payload, block, ctx),
                                 ensure_ascii=False).encode("utf-8")
            except Exception:
                pass
            self.send_response(response.status)
            for name, value in _safe_response_headers(response.headers):
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            self.wfile.write(raw)
            self.wfile.flush()
            return

        # Zero-copy chunked stream pass-through
        completed_cleanly = False
        self.send_response(response.status)
        for name, value in _safe_response_headers(response.headers):
            self.send_header(name, value)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            while True:
                chunk = response.read1(64 * 1024)
                if not chunk:
                    completed_cleanly = True
                    break
                self.wfile.write((b"%x\r\n" % len(chunk)) + chunk + b"\r\n")
                self.wfile.flush()
            if completed_cleanly:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                response.close()
        finally:
            if completed_cleanly:
                _UPSTREAM_POOL.release(conn, response, bucket)
            else:
                try:
                    conn.close()
                except Exception:
                    pass

    def do_GET(self):
        try:
            self._forward()
        except ValueError as exc:
            self._send_json(400, {"error": {"message": str(exc), "type": "invalid_request"}})
        except Exception:
            self._send_json(502, {"error": {"message": "Qoder filter processing failed",
                                            "type": "proxy_error"}})

    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET


def start_background_server(host=None, port=None):
    addr = (host or LISTEN[0], int(port or LISTEN[1]))
    srv = BoundedThreadingHTTPServer(addr, FilterHandler)
    t = threading.Thread(target=srv.serve_forever, name="qoder-filter-server", daemon=True)
    t.start()
    return srv, t


def main():
    print(f"Starting qoder-model-filter on {LISTEN[0]}:{LISTEN[1]} -> {UPSTREAM}")
    BoundedThreadingHTTPServer(LISTEN, FilterHandler).serve_forever()


if __name__ == "__main__":
    main()
