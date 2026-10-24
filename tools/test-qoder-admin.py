#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for qoder-admin."""
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
MODULE_PATH = os.path.join(os.path.dirname(HERE), "qoder-admin.py")

FAILS = []


def check(cond, label, extra=""):
    status = "OK" if cond else "FAIL"
    print(f"{label:<55} {status}" + (f"  ({extra})" if extra else ""))
    if not cond:
        FAILS.append(label)


def load_admin_module():
    spec = importlib.util.spec_from_file_location("qoder_admin_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    print("Testing Qoder Admin Control Panel & APIs...\n")
    adm = load_admin_module()

    with tempfile.TemporaryDirectory() as tmp:
        # Configure temporary isolated storage paths
        adm.ADMIN_DIR = tmp
        adm.CRED_FILE = os.path.join(tmp, "credentials.txt")
        adm.KEYS_FILE = os.path.join(tmp, "keys.json")
        adm.QODER_BLOCK_FILE = os.path.join(tmp, "blocked-models.json")
        adm.QODER_SCHEDULE_FILE = os.path.join(tmp, "qoder-schedule.json")
        adm.HASH_FILE = os.path.join(tmp, "basicauth.hash")

        # 1. Password and Session Security
        default_pw = adm.get_admin_password()
        check(default_pw == "admin123456", "Default admin password correctly generated")
        check(adm.verify_admin_password("admin123456"), "Verify default admin password matches")
        check(not adm.verify_admin_password("wrong-password"), "Reject incorrect admin password")

        # Session token generation & validation
        sess = adm.create_session()
        check(adm.validate_session(sess), "Validate newly created session token")
        check(not adm.validate_session("invalid-session-token"), "Reject non-existent session token")

        # Password modification
        ok, msg = adm.change_admin_password("wrong-old", "newsecret123")
        check(not ok, "Reject password change with incorrect old password")

        ok, msg = adm.change_admin_password("admin123456", "short")
        check(not ok, "Enforce minimum password length requirement")

        ok, msg = adm.change_admin_password("admin123456", "newadmin888")
        check(ok and adm.verify_admin_password("newadmin888"), "Successfully update admin password")

        # 2. API Key Management (CRUD)
        key1 = adm.create_key("Production Key")
        check(
            key1["key"].startswith("sk-qd-") and key1["enabled"] is True,
            "Create key with correct sk-qd- prefix and enabled flag"
        )

        keys_data = adm.load_keys()
        check(len(keys_data.get("keys", [])) == 1, "Keys list persisted and contains 1 key")

        # Toggle key
        toggled = adm.toggle_key(key1["id"])
        check(toggled["enabled"] is False, "Toggle key from enabled to disabled")
        keys_data2 = adm.load_keys()
        check(keys_data2["keys"][0]["enabled"] is False, "Key disabled state persisted")

        adm.toggle_key(key1["id"])
        keys_data3 = adm.load_keys()
        check(keys_data3["keys"][0]["enabled"] is True, "Toggle key back to enabled")

        # Delete key
        adm.delete_key(key1["id"])
        keys_data4 = adm.load_keys()
        check(len(keys_data4.get("keys", [])) == 0, "Delete key successfully removes entry")

        # 3. Model Filter & Context Length Configuration
        init_filter = adm.qoder_blocked_models_conf()
        check(init_filter["models"] == [] and init_filter["context_length"] is None, "Empty blocked models on init")

        saved_filter = adm.save_qoder_blocked_models(["Auto", "Auto", "MiniMax-M2.7"], 360000)
        check(
            saved_filter["models"] == ["Auto", "MiniMax-M2.7"] and saved_filter["context_length"] == 360000,
            "Save and deduplicate blocked models with context override"
        )
        reloaded_filter = adm.qoder_blocked_models_conf()
        check(reloaded_filter == saved_filter, "Reload blocked models configuration from disk")

        # 4. Schedule Configuration
        init_sched = adm.qoder_schedule_conf()
        check(init_sched["enabled"] is True and "10:05" in init_sched["times"], "Default schedule configuration")

        saved_sched = adm.save_qoder_schedule(True, ["9", "21:30"], jitter_minutes=10)
        check(
            saved_sched["times"] == ["09:00", "21:30"] and saved_sched["jitter_minutes"] == 10,
            "Normalize schedule hours and persist jitter setting"
        )

        # 5. End-to-End HTTP Server verification
        srv, t = adm.start_background_admin(host="127.0.0.1", port=0)
        port = srv.server_address[1]

        # GET /healthz
        req_health = urllib.request.Request(f"http://127.0.0.1:{port}/healthz")
        with urllib.request.urlopen(req_health, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            check(resp.status == 200 and data.get("ok") is True, "Admin healthz responds 200")

        # Unauthenticated request to /api/keys -> 401
        req_unauth = urllib.request.Request(f"http://127.0.0.1:{port}/api/keys")
        try:
            urllib.request.urlopen(req_unauth, timeout=5)
            check(False, "Unauthenticated API request returned 401")
        except urllib.error.HTTPError as e:
            check(e.code == 401, "Unauthenticated API request correctly rejected with 401")

        # Authenticated with Bearer password
        req_auth = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/keys",
            headers={"Authorization": "Bearer newadmin888"}
        )
        with urllib.request.urlopen(req_auth, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            check(resp.status == 200 and isinstance(data.get("keys"), list), "Authenticated GET /api/keys responds 200")

        # POST /api/keys create
        req_create_key = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/keys",
            data=json.dumps({"name": "AgentKey"}).encode("utf-8"),
            headers={"Authorization": "Bearer newadmin888", "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_create_key, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            check(resp.status == 200 and data.get("key", "").startswith("sk-qd-"), "POST /api/keys creates new key")
            new_kid = data.get("id")

        # POST /api/keys/toggle
        req_toggle = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/keys/toggle",
            data=json.dumps({"id": new_kid}).encode("utf-8"),
            headers={"Authorization": "Bearer newadmin888", "Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req_toggle, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            check(resp.status == 200 and data.get("enabled") is False, "POST /api/keys/toggle disables key")

        # Clean shutdown
        threading.Thread(target=srv.shutdown, daemon=True).start()
        srv.server_close()

    if FAILS:
        print(f"\nFailed tests ({len(FAILS)}): {FAILS}")
        return 1
    print("\nAll tests passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
