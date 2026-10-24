#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive test suite for qoder-model-filter."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(os.path.dirname(HERE), "qoder-model-filter.py")

FAILS = []


def check(cond, label, extra=""):
    status = "OK" if cond else "FAIL"
    print(f"{label:<55} {status}" + (f"  ({extra})" if extra else ""))
    if not cond:
        FAILS.append(label)


def load_filter_module():
    spec = importlib.util.spec_from_file_location("qoder_model_filter_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class MockUpstreamHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/v1/models":
            body = json.dumps({
                "object": "list",
                "data": [
                    {"id": "Auto", "context_length": 180000, "aliases": ["qoder-auto"]},
                    {"id": "Qwen3.8-Flash", "context_length": 180000, "max_input_tokens": 180000}
                ]
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "14")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}')

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        body = b'{"id":"chatcmpl-test","choices":[{"message":{"content":"hello"}}]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    print("Testing Qoder Model Filter Core Logic & End-to-End HTTP...\n")
    m = load_filter_module()

    with tempfile.TemporaryDirectory() as tmp:
        cfg_path = os.path.join(tmp, "blocked-models.json")
        keys_path = os.path.join(tmp, "keys.json")

        # 1. Config loading & resilience tests
        block, ctx = m._config(cfg_path)
        check(block == set() and ctx is None, "Fallback to empty set on missing config file")

        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"models": ["Auto", "MiniMax-M2.7"], "context_length": 360000}, f)
        block, ctx = m._config(cfg_path)
        check(block == {"auto", "minimax-m2.7"} and ctx == 360000, "Load blocked models and context length")

        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(["Auto", "GLM-5"], f)
        block, ctx = m._config(cfg_path)
        check(block == {"auto", "glm-5"} and ctx is None, "Backwards compatibility with raw list config")

        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write("{invalid-json-content")
        block, ctx = m._config(cfg_path)
        check(block == set() and ctx is None, "Fail-safe fallback on corrupted config file")

        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"models": ["Auto"], "context_length": "invalid_number"}, f)
        block, ctx = m._config(cfg_path)
        check(ctx is None, "Gracefully ignore non-integer context length")

        # 2. Rewrite models pure function tests
        payload = {
            "object": "list",
            "data": [
                {"id": "Auto", "context_length": 180000},
                {"id": "Qwen3.8-Flash", "context_length": 180000, "max_input_tokens": 180000},
                {"id": "GLM-5.3"},
                "non-dict-item"
            ]
        }
        rewritten = m.rewrite_models(payload, {"auto"}, 360000)
        remaining_ids = [x.get("id") if isinstance(x, dict) else x for x in rewritten["data"]]
        check("Auto" not in remaining_ids, "Blocked model excluded from catalog")

        flash = [x for x in rewritten["data"] if isinstance(x, dict) and x.get("id") == "Qwen3.8-Flash"][0]
        check(
            flash["context_length"] == 360000 and flash["max_input_tokens"] == 360000,
            "Context length and max input tokens correctly overridden"
        )

        glm = [x for x in rewritten["data"] if isinstance(x, dict) and x.get("id") == "GLM-5.3"][0]
        check("context_length" not in glm, "Do not add context_length if not originally present")
        check(len(rewritten["data"]) == 3, "Preserve non-dict entries intact")

        # 3. Model extraction fast scanner tests
        small_body = b'{"model": "MiniMax-M2.7", "messages": [{"role": "user", "content": "hi"}]}'
        check(m._extract_model_fast(small_body) == "MiniMax-M2.7", "Extract model from small JSON payload")

        large_body = b'{"messages": [{"content": "' + (b"A" * 100000) + b'"}], "model": "Qwen3.8-Max"}'
        check(m._extract_model_fast(large_body) == "Qwen3.8-Max", "Fast regex scanner for payloads over 64KB")
        check(m._extract_model_fast(b"") == "", "Empty body returns empty model string")

        # 4. Alias matching and blocking tests
        aliases = {"auto": {"auto", "qoder-auto", "auto-best"}}
        check(m._is_blocked("Auto", {"auto"}, aliases), "Exact model ID matches block set")
        check(m._is_blocked("qoder-auto", {"auto"}, aliases), "Model alias matches block set")
        check(not m._is_blocked("qwen-plus", {"auto"}, aliases), "Allowed model not blocked")

        # 5. Multi-tenant API key management & Fail-Closed caching tests
        missing_keys = m.load_valid_keys(os.path.join(tmp, "non-existent-keys.json"))
        check(missing_keys == frozenset(), "Fail-Closed: Missing keys file yields empty frozenset")

        keys_data = {
            "keys": [
                {"key": "sk-qd-valid-1", "enabled": True},
                {"key": "sk-qd-valid-2", "enabled": True},
                {"key": "sk-qd-disabled", "enabled": False},
                {"key": "  ", "enabled": True}
            ]
        }
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(keys_data, f)

        loaded_keys = m.load_valid_keys(keys_path)
        check(
            loaded_keys == frozenset({"sk-qd-valid-1", "sk-qd-valid-2"}),
            "Load valid keys and exclude disabled/empty keys"
        )

        cached_keys = m.load_valid_keys(keys_path)
        check(cached_keys is loaded_keys, "Cache hit returns identical frozenset instance")

        time.sleep(0.01)
        keys_data["keys"].append({"key": "sk-qd-valid-3", "enabled": True})
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(keys_data, f)

        reloaded_keys = m.load_valid_keys(keys_path)
        check("sk-qd-valid-3" in reloaded_keys, "Hot reloads valid keys when file modified")

        time.sleep(0.01)
        with open(keys_path, "w", encoding="utf-8") as f:
            f.write("corrupted-json-content")
        corrupted_keys = m.load_valid_keys(keys_path)
        check(corrupted_keys == frozenset(), "Fail-Closed on corrupted keys file")

        # 6. End-to-End HTTP Server verification
        mock_up = HTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        mock_up_port = mock_up.server_port
        t_up = threading.Thread(target=mock_up.serve_forever, daemon=True)
        t_up.start()

        m.UPSTREAM = f"http://127.0.0.1:{mock_up_port}"
        m.CONFIG_FILE = cfg_path
        m.KEYS_FILE = keys_path
        m.KEY_CHECK = True

        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump({"keys": [{"key": "sk-qd-testkey", "enabled": True}]}, f)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump({"models": ["Auto"], "context_length": 320000}, f)

        filter_srv, filter_thread = m.start_background_server(host="127.0.0.1", port=0)
        filter_port = filter_srv.server_address[1]

        # GET /healthz
        req_health = urllib.request.Request(f"http://127.0.0.1:{filter_port}/healthz")
        with urllib.request.urlopen(req_health, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            check(resp.status == 200 and data.get("ok") is True, "Healthz endpoint responds 200 without auth")

        # Request without key -> 401
        req_no_auth = urllib.request.Request(f"http://127.0.0.1:{filter_port}/v1/models")
        try:
            urllib.request.urlopen(req_no_auth, timeout=5)
            check(False, "Unauthorized request blocked with 401")
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode())
            check(
                e.code == 401 and body.get("error", {}).get("code") == "invalid_api_key",
                "Unauthorized request returns standard OpenAI 401 schema"
            )

        # Request with blocked model -> 404
        req_blocked = urllib.request.Request(
            f"http://127.0.0.1:{filter_port}/v1/chat/completions",
            data=b'{"model":"Auto","messages":[{"role":"user","content":"hi"}]}',
            headers={"Authorization": "Bearer sk-qd-testkey", "Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req_blocked, timeout=5)
            check(False, "Blocked model call returned 404")
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode())
            check(
                e.code == 404 and body.get("error", {}).get("code") == "model_not_found",
                "Blocked model returns standard 404 error"
            )

        # Request with valid key to models -> 200 rewritten
        req_models = urllib.request.Request(
            f"http://127.0.0.1:{filter_port}/v1/models",
            headers={"Authorization": "Bearer sk-qd-testkey"}
        )
        with urllib.request.urlopen(req_models, timeout=5) as resp:
            models_data = json.loads(resp.read().decode())
            m_ids = [x.get("id") for x in models_data.get("data", [])]
            check(
                resp.status == 200 and "Auto" not in m_ids and "Qwen3.8-Flash" in m_ids,
                "Valid key passes through and models list rewritten"
            )

        # Graceful shutdown
        threading.Thread(target=filter_srv.shutdown, daemon=True).start()
        filter_srv.server_close()
        threading.Thread(target=mock_up.shutdown, daemon=True).start()
        mock_up.server_close()

    if FAILS:
        print(f"\nFailed tests ({len(FAILS)}): {FAILS}")
        return 1
    print("\nAll tests passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
