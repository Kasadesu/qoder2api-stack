#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qoder Administration Web Console & Automation Daemon."""
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import random
import re
import secrets
import subprocess
import sys
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlsplit
from urllib.request import Request, urlopen

VERSION = "1.0.0"

LISTEN_HOST = os.environ.get("QODER_ADMIN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("QODER_ADMIN_PORT", 8792))
LISTEN = (LISTEN_HOST, LISTEN_PORT)

ADMIN_DIR = os.environ.get("QODER_ADMIN_DIR", "/opt/qoder2api/admin")
QODER_CFG_FILE = os.environ.get("QODER_CFG_FILE", os.path.join(ADMIN_DIR, "qoder.json"))
QODER_BLOCK_FILE = os.environ.get("QODER_BLOCK_FILE", "/opt/qoder2api/blocked-models.json")
QODER_SCHEDULE_FILE = os.environ.get("QODER_SCHEDULE_FILE", os.path.join(ADMIN_DIR, "qoder-schedule.json"))
KEYS_FILE = os.environ.get("QODER_KEYS_FILE", os.path.join(ADMIN_DIR, "keys.json"))
CRED_FILE = os.environ.get("QODER_CRED_FILE", os.path.join(ADMIN_DIR, "credentials.txt"))
HASH_FILE = os.environ.get("QODER_HASH_FILE", os.path.join(ADMIN_DIR, "basicauth.hash"))
CADDY_FILE = os.environ.get("CADDY_FILE", "/etc/caddy/Caddyfile")

KEY_PREFIX = "sk-qd-"
ADMIN_PASSWORD_MIN = 8
RECENT_USAGE_LIMIT = 100

_STATE_LOCK = threading.RLock()
_PANEL_CACHE = {"token": "", "at": 0.0}
_SESSIONS = {}  # session_token -> expire_time

QODER_SCHEDULE_LOCK = threading.RLock()
QODER_SCHEDULE_STATE = {"fired": "", "last_ok": None, "last_error": "", "last_at": 0}


# --- Helper utilities

def _atomic_write_json(filepath, data, mode=0o600):
    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    tmp = filepath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, filepath)
    try:
        os.chmod(filepath, mode)
    except Exception:
        pass


def _num(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# --- Credentials & Session Security

def get_admin_password():
    if os.path.exists(CRED_FILE):
        try:
            with open(CRED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    s = line.strip()
                    if s.startswith("管理页登录密码:"):
                        return s.split("管理页登录密码:", 1)[1].strip()
                    if s.startswith("password:"):
                        return s.split("password:", 1)[1].strip()
        except Exception:
            pass
    # Fallback / initialize default
    default_pw = "admin123456"
    try:
        os.makedirs(ADMIN_DIR, exist_ok=True)
        with open(CRED_FILE, "w", encoding="utf-8") as f:
            f.write("管理页登录账号: admin\n")
            f.write(f"管理页登录密码: {default_pw}\n")
        os.chmod(CRED_FILE, 0o600)
    except Exception:
        pass
    return default_pw


def verify_admin_password(password):
    current = get_admin_password()
    return bool(password) and secrets.compare_digest(current, str(password).strip())


def sync_caddy_hash(new_password):
    try:
        res = subprocess.run(
            ["caddy", "hash-password", "--plaintext", new_password],
            capture_output=True, text=True, timeout=10
        )
        if res.returncode == 0:
            newhash = res.stdout.strip()
            with open(HASH_FILE, "w", encoding="utf-8") as f:
                f.write(newhash)
            try:
                os.chmod(HASH_FILE, 0o600)
            except Exception:
                pass
            if os.path.exists(CADDY_FILE):
                with open(CADDY_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                pattern = re.compile(r"(admin\s+)(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53})")
                new_content, n = pattern.subn(lambda m: m.group(1) + newhash, content)
                if n > 0:
                    with open(CADDY_FILE, "w", encoding="utf-8") as f:
                        f.write(new_content)
                    subprocess.run(["caddy", "reload", "--config", CADDY_FILE], capture_output=True, check=False)
            return True, "Synced Caddy hash successfully"
    except Exception as e:
        return False, str(e)
    return False, "caddy binary not available"


def change_admin_password(old_pw, new_pw):
    if not verify_admin_password(old_pw):
        return False, "原密码错误"
    new_pw = str(new_pw or "").strip()
    if len(new_pw) < ADMIN_PASSWORD_MIN:
        return False, f"密码至少需要 {ADMIN_PASSWORD_MIN} 位"
    os.makedirs(ADMIN_DIR, exist_ok=True)
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        f.write("管理页登录账号: admin\n")
        f.write(f"管理页登录密码: {new_pw}\n")
    try:
        os.chmod(CRED_FILE, 0o600)
    except Exception:
        pass
    sync_caddy_hash(new_pw)
    return True, "密码已更新"


def create_session():
    token = secrets.token_hex(24)
    with _STATE_LOCK:
        _SESSIONS[token] = time.time() + 86400 * 7  # 7 days
    return token


def validate_session(token):
    if not token:
        return False
    now = time.time()
    with _STATE_LOCK:
        expire = _SESSIONS.get(token)
        if expire and expire > now:
            return True
        if token in _SESSIONS:
            del _SESSIONS[token]
    return False


# --- Qoder Upstream Gateway Calls

def qoder_conf():
    try:
        with open(QODER_CFG_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _qoder_panel_token():
    now = time.time()
    with _STATE_LOCK:
        if _PANEL_CACHE["token"] and now - _PANEL_CACHE["at"] < 1800:
            return _PANEL_CACHE["token"]
        cfg = qoder_conf()
        base = str(cfg.get("base_url") or "http://127.0.0.1:8790").rstrip("/")
        pwd = str(cfg.get("panel_password") or "")
        if not base or not pwd:
            raise RuntimeError("未配置 Qoder 网关面板密码（qoder.json 缺少 panel_password）")
        req = Request(
            base + "/panel/login",
            data=json.dumps({"password": pwd}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urlopen(req, timeout=15) as resp:
            d = json.loads(resp.read().decode("utf-8", "ignore"))
        tok = str((d or {}).get("token") or "")
        if not tok:
            raise RuntimeError("Qoder 面板登录未返回令牌")
        _PANEL_CACHE["token"] = tok
        _PANEL_CACHE["at"] = now
        return tok


def _qoder_call(path, method="GET", body=None, panel=False, timeout=30):
    cfg = qoder_conf()
    base = str(cfg.get("base_url") or "http://127.0.0.1:8790").rstrip("/")
    if not base:
        raise RuntimeError("未配置 Qoder 网关 base_url")
    headers = {"Accept": "application/json"}
    key = str(cfg.get("api_key") or "")
    if key:
        headers["Authorization"] = "Bearer " + key
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if panel:
        headers["X-Panel-Token"] = _qoder_panel_token()
    req = Request(base + path, data=data, headers=headers, method=method)
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "ignore"))


# --- Accounts Pool & Credits

def qoder_accounts_info():
    d = _qoder_call("/accounts", panel=True)
    accounts = []
    for a in (d.get("accounts") or []):
        if not isinstance(a, dict):
            continue
        uid = str(a.get("uid") or a.get("id") or "")
        accounts.append({
            "uid": uid,
            "name": str(a.get("nickname") or a.get("name") or uid or "账号"),
            "realm": str(a.get("realm") or ""),
            "enabled": bool(a.get("enabled", True)),
            "plan": str(a.get("plan") or a.get("plan_name") or a.get("platform") or ""),
        })
    try:
        summary = _qoder_call("/credits/summary")
        totals = (summary or {}).get("totals") or {}
    except Exception:
        totals = {}
    return {
        "ok": True,
        "accounts": accounts,
        "usable": d.get("usable"),
        "totals": totals,
        "configured": bool(qoder_conf().get("base_url"))
    }


def qoder_login_start(realm="cn"):
    d = _qoder_call("/accounts/login/start", method="POST",
                    body={"platform": "CLI", "realm": realm}, panel=True)
    url = str(d.get("authUrl") or "")
    if not url:
        raise RuntimeError("Qoder 未返回授权链接")
    return {
        "ok": True,
        "auth_url": url,
        "state": str(d.get("state") or ""),
        "realm": str(d.get("realm") or realm)
    }


def qoder_login_poll(state):
    q = quote(str(state or ""))
    return _qoder_call("/accounts/login/poll?state=" + q, panel=True, timeout=20)


def qoder_login_cancel(state):
    return _qoder_call("/accounts/login/cancel", method="POST",
                       body={"state": str(state or "")}, panel=True, timeout=20)


def qoder_checkin():
    with _STATE_LOCK:
        return _qoder_call("/accounts/checkin", method="POST", body={}, panel=True, timeout=180)


def qoder_account_action(uid, action):
    uid = str(uid or "").strip()
    if not uid:
        raise ValueError("缺少账号 uid")
    if action == "delete":
        return _qoder_call("/accounts/delete", method="POST", body={"uid": uid}, panel=True)
    if action in ("enable", "disable"):
        return _qoder_call("/accounts/set", method="POST",
                           body={"uid": uid, "enabled": action == "enable"}, panel=True)
    if action == "refresh":
        return _qoder_call("/accounts/refresh", method="POST", body={"uid": uid}, panel=True, timeout=90)
    raise ValueError("未知账号操作: " + str(action))


def qoder_pool():
    d = _qoder_call("/accounts", panel=True)
    accounts = []
    t_remain = t_used = t_size = 0
    for a in (d.get("accounts") or []):
        if not isinstance(a, dict):
            continue
        c = a.get("credits") or {}
        remain = _num(c.get("remain"))
        used = _num(c.get("used"))
        size = _num(c.get("size"))
        t_remain += remain
        t_used += used
        t_size += size
        pkgs = []
        for p in (c.get("packages") or []):
            if isinstance(p, dict):
                pkgs.append({
                    "name": str(p.get("name") or ""),
                    "remain": _num(p.get("remain")),
                    "size": _num(p.get("size"))
                })
        accounts.append({
            "uid": str(a.get("uid") or ""),
            "nickname": str(a.get("nickname") or a.get("uid") or "账号"),
            "realm": str(a.get("realm") or ""),
            "domain": str(a.get("domain") or ""),
            "plan": str(a.get("platform") or ""),
            "enabled": bool(a.get("enabled", True)),
            "remain": remain, "used": used, "size": size,
            "exceeded": bool(c.get("exceeded")),
            "packages": pkgs,
            "last_error": str(a.get("lastError") or "")[:120],
            "in_cooldown": bool(a.get("inCooldown")),
        })
    pct = int(round(t_remain * 100.0 / t_size)) if t_size > 0 else 0
    checkin = {}
    try:
        t = _qoder_call("/tasks", panel=True, timeout=60)
        s = t.get("summary") or {}
        checkin = {
            "streak_days": s.get("streak_days"),
            "energy": s.get("energy"),
            "tasks": [{
                "code": str(x.get("task_code") or ""),
                "name": str(x.get("name") or ""),
                "desc": str(x.get("description") or ""),
                "url": str(x.get("jump_url") or ""),
                "status": str(x.get("status") or ""),
            } for x in (t.get("tasks") or []) if isinstance(x, dict)],
        }
    except Exception as e:
        checkin = {"error": str(e)[:200]}
    return {
        "ok": True,
        "configured": bool(qoder_conf().get("base_url")),
        "totals": {
            "remain": t_remain, "used": t_used, "size": t_size,
            "accounts": len(accounts), "pct": pct
        },
        "accounts": accounts,
        "checkin": checkin
    }


def qoder_credits_refresh():
    return _qoder_call("/accounts/credits", method="POST", body={}, panel=True, timeout=180)


def qoder_usage():
    out = {"ok": True}
    try:
        u = _qoder_call("/usage", panel=True, timeout=30)
        out["all_time"] = {k: u.get(k) for k in (
            "requests", "errors", "prompt_tokens", "completion_tokens",
            "reasoning_tokens", "cached_tokens", "total_tokens", "credit"
        )}
        out["since"] = str(u.get("since") or "")
        out["by_model"] = u.get("by_model") or {}
    except Exception as e:
        out["all_time"] = {}
        out["usage_error"] = str(e)[:150]
    return out


def qoder_recent_usage(limit=RECENT_USAGE_LIMIT):
    d = _qoder_call(f"/usage/recent?limit={max(1, int(limit))}", panel=True, timeout=30)
    key_dict = {
        str(k.get("key", "")).strip(): str(k.get("name", "")).strip()
        for k in load_keys().get("keys", [])
        if isinstance(k, dict) and k.get("key") and k.get("name")
    }
    names = {}
    try:
        for a in (_qoder_call("/accounts", panel=True, timeout=25).get("accounts") or []):
            if isinstance(a, dict) and a.get("uid"):
                names[str(a["uid"])] = str(a.get("nickname") or a["uid"])
    except Exception:
        names = {}

    out = []
    for r in (d.get("rows") or []):
        if not isinstance(r, dict):
            continue
        uid = str(r.get("account") or "")
        prompt = _num(r.get("prompt_tokens"))
        cached = _num(r.get("cached_tokens"))
        rate = None
        if cached is not None and prompt > 0:
            rate = round(float(cached) / float(prompt), 4)
        raw_key = str(r.get("api_key") or r.get("key") or "")
        masked_key = key_dict.get(raw_key) or (raw_key[:8] + "..." if len(raw_key) > 8 else raw_key)
        out.append({
            "at": str(r.get("iso") or ""),
            "uid": uid,
            "nickname": names.get(uid, uid),
            "api_key": masked_key,
            "realm": str(r.get("realm") or ""),
            "model": str(r.get("model") or ""),
            "mode": "stream" if r.get("stream") else "sync",
            "status": r.get("status", 200),
            "input_tokens": prompt,
            "cached_input_tokens": cached,
            "cache_hit_rate": rate,
            "output_tokens": _num(r.get("completion_tokens")),
            "total_tokens": _num(r.get("total_tokens")),
            "credits": r.get("credit"),
        })
    return {"ok": True, "records": out}


# --- Model Catalog & Blocked Filtering

def _qoder_rate_text(m):
    eff = _float(m.get("price_factor"))
    peak = _float(m.get("price_factor_peak"))
    valley = _float(m.get("price_factor_valley"))
    orig = _float(m.get("original_price_factor"))

    if eff == 0.0:
        base = orig if orig is not None else peak
        return "免费" + (f" (原 x{base:g})" if base else "")
    if peak is not None and valley is not None and peak != valley:
        return f"峰 x{peak:g} / 谷 x{valley:g}"
    v = eff if eff is not None else (peak if peak is not None else valley)
    return f"x{v:g}" if v is not None else "未返回"


def qoder_blocked_models_conf():
    try:
        with open(QODER_BLOCK_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return {"models": [], "context_length": None}
    if isinstance(d, list):
        return {"models": [str(x).strip() for x in d if str(x).strip()], "context_length": None}
    if isinstance(d, dict):
        return {
            "models": [str(x).strip() for x in (d.get("models") or []) if str(x).strip()],
            "context_length": d.get("context_length")
        }
    return {"models": [], "context_length": None}


def save_qoder_blocked_models(models, context_length=None):
    clean_models = sorted(list({str(m).strip() for m in (models or []) if str(m).strip()}))
    ctx = None
    if context_length is not None and str(context_length).strip() != "":
        try:
            ctx = int(context_length)
        except (ValueError, TypeError):
            ctx = None
    payload = {"models": clean_models, "context_length": ctx}
    _atomic_write_json(QODER_BLOCK_FILE, payload, mode=0o644)
    return payload


def qoder_model_rows():
    cfg = qoder_conf()
    base = str(cfg.get("base_url") or "http://127.0.0.1:8790").rstrip("/")
    if not base:
        raise RuntimeError("未配置 Qoder 网关（qoder.json）")
    req = Request(base + "/v1/models", headers={
        "Authorization": "Bearer " + str(cfg.get("api_key") or ""),
        "Accept": "application/json",
    })
    with urlopen(req, timeout=30) as resp:
        d = json.loads(resp.read().decode("utf-8", "ignore"))

    blocked_info = qoder_blocked_models_conf()
    blocked_set = {x.lower() for x in blocked_info["models"]}

    rows = []
    for m in (d.get("data") or []):
        if not isinstance(m, dict):
            continue
        mid = str(m.get("id") or "").strip()
        if not mid:
            continue
        rows.append({
            "id": mid,
            "blocked": mid.lower() in blocked_set,
            "rate_text": _qoder_rate_text(m),
            "context_length": m.get("context_length"),
            "max_input_tokens": m.get("max_input_tokens"),
            "aliases": m.get("aliases") or []
        })
    return {
        "ok": True,
        "models": rows,
        "blocked_count": len(blocked_set),
        "context_override": blocked_info.get("context_length")
    }


# --- Schedule Management

def _qoder_norm_times(values):
    out = set()
    for v in (values or []):
        s = str(v).strip()
        if not s:
            continue
        if s.isdigit():
            h = int(s)
            if not (0 <= h <= 23):
                raise ValueError("小时必须在 0-23")
            out.add("%02d:00" % h)
            continue
        m = re.match(r"^(\d{1,2}):(\d{2})$", s)
        if not m:
            raise ValueError("时间点格式应为 HH:MM 或纯数字小时")
        h, mi = int(m.group(1)), int(m.group(2))
        if not (0 <= h <= 23 and 0 <= mi <= 59):
            raise ValueError("时间点超出合法范围")
        out.add("%02d:%02d" % (h, mi))
    return sorted(out)


def qoder_schedule_conf():
    cfg = {"enabled": True, "times": ["10:05", "21:30"], "jitter_minutes": 5}
    try:
        with open(QODER_SCHEDULE_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
        if isinstance(d, dict):
            cfg["enabled"] = bool(d.get("enabled", True))
            raw = d.get("times") or d.get("hours")
            ts = _qoder_norm_times(raw) if raw else []
            if ts:
                cfg["times"] = ts
            cfg["jitter_minutes"] = max(0, min(60, _num(d.get("jitter_minutes"), 5)))
    except Exception:
        pass
    return cfg


def save_qoder_schedule(enabled, times, jitter_minutes=5):
    ts = _qoder_norm_times(times)
    if not ts:
        raise ValueError("至少需要一个执行时点")
    if len(ts) > 24:
        raise ValueError("最多配置 24 个执行时点")
    jitter = max(0, min(60, _num(jitter_minutes, 5)))
    cfg = {"enabled": bool(enabled), "times": ts, "jitter_minutes": jitter}
    with QODER_SCHEDULE_LOCK:
        _atomic_write_json(QODER_SCHEDULE_FILE, cfg, mode=0o644)
    return cfg


def _qoder_next_run(times, now=None):
    if not times:
        return ""
    now = now or time.localtime()
    cur = now.tm_hour * 60 + now.tm_min
    ts = sorted(times)
    for t in ts:
        if int(t[:2]) * 60 + int(t[3:]) > cur:
            return time.strftime("%Y-%m-%d ", now) + t
    nxt = time.localtime(time.mktime(now) + 86400)
    return time.strftime("%Y-%m-%d ", nxt) + ts[0]


def qoder_schedule_info():
    cfg = qoder_schedule_conf()
    with QODER_SCHEDULE_LOCK:
        st = dict(QODER_SCHEDULE_STATE)
    return {
        "ok": True,
        "enabled": cfg["enabled"],
        "times": cfg["times"],
        "jitter_minutes": cfg.get("jitter_minutes", 0),
        "next_run": _qoder_next_run(cfg["times"]) if cfg["enabled"] else "",
        "last_fired": st.get("fired") or "",
        "last_ok": st.get("last_ok"),
        "last_error": st.get("last_error") or "",
        "last_at": st.get("last_at") or 0,
        "server_time": time.strftime("%Y-%m-%d %H:%M:%S")
    }


def _qoder_schedule_due(cfg, now, jitter_offset=0):
    if not cfg.get("enabled"):
        return False
    # Target minute adjusted by jitter
    target_min = now.tm_hour * 60 + now.tm_min - jitter_offset
    if target_min < 0:
        return False
    h = target_min // 60
    m = target_min % 60
    return ("%02d:%02d" % (h, m)) in (cfg.get("times") or [])


def _qoder_schedule_loop():
    current_jitter = 0
    last_jitter_day = -1
    while True:
        try:
            time.sleep(30)
            cfg = qoder_schedule_conf()
            if not cfg.get("enabled"):
                continue
            now = time.localtime()
            if now.tm_yday != last_jitter_day:
                max_j = cfg.get("jitter_minutes", 0)
                current_jitter = random.randint(0, max_j) if max_j > 0 else 0
                last_jitter_day = now.tm_yday

            if not _qoder_schedule_due(cfg, now, current_jitter):
                continue

            stamp = time.strftime("%Y-%m-%d %H:%M", now)
            with QODER_SCHEDULE_LOCK:
                if QODER_SCHEDULE_STATE["fired"] == stamp:
                    continue
                QODER_SCHEDULE_STATE["fired"] = stamp

            try:
                qoder_checkin()
                with QODER_SCHEDULE_LOCK:
                    QODER_SCHEDULE_STATE["last_ok"] = True
                    QODER_SCHEDULE_STATE["last_error"] = ""
                    QODER_SCHEDULE_STATE["last_at"] = int(time.time())
            except Exception as e:
                with QODER_SCHEDULE_LOCK:
                    QODER_SCHEDULE_STATE["last_ok"] = False
                    QODER_SCHEDULE_STATE["last_error"] = str(e)[:200]
                    QODER_SCHEDULE_STATE["last_at"] = int(time.time())
        except Exception:
            pass


def start_qoder_scheduler():
    t = threading.Thread(target=_qoder_schedule_loop, name="qoder-scheduler", daemon=True)
    t.start()
    return t


# --- Multi-tenant API Keys Management

def load_keys():
    try:
        with open(KEYS_FILE, "r", encoding="utf-8") as f:
            d = json.load(f)
            if isinstance(d.get("keys"), list):
                return d
    except Exception:
        pass
    return {"keys": []}


def save_keys(d):
    _atomic_write_json(KEYS_FILE, d, mode=0o600)


def create_key(name):
    name = str(name or "").strip()[:40] or "Default Key"
    raw_key = KEY_PREFIX + secrets.token_urlsafe(24)
    item = {
        "id": secrets.token_hex(6),
        "name": name,
        "key": raw_key,
        "platform": "qoder",
        "enabled": True,
        "created_at": int(time.time())
    }
    with _STATE_LOCK:
        data = load_keys()
        data["keys"].insert(0, item)
        save_keys(data)
    return item


def toggle_key(key_id):
    with _STATE_LOCK:
        data = load_keys()
        for k in data.get("keys", []):
            if k.get("id") == key_id or k.get("key") == key_id:
                k["enabled"] = not k.get("enabled", True)
                save_keys(data)
                return {"ok": True, "enabled": k["enabled"]}
    raise ValueError("Key not found")


def delete_key(key_id):
    with _STATE_LOCK:
        data = load_keys()
        before = len(data.get("keys", []))
        data["keys"] = [k for k in data.get("keys", []) if k.get("id") != key_id and k.get("key") != key_id]
        if len(data["keys"]) != before:
            save_keys(data)
            return {"ok": True}
    raise ValueError("Key not found")


# --- Obsidian Minimal UI Template

UI_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Qoder API Control Panel</title>
<style>
:root {
  --bg-main: #111113;
  --bg-card: #18181b;
  --bg-card-sub: #222227;
  --border: #2e2e36;
  --accent: #7c3aed;
  --accent-hover: #6d28d9;
  --text-main: #f4f4f5;
  --text-muted: #a1a1aa;
  --success: #10b981;
  --danger: #ef4444;
  --warning: #f59e0b;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
body { background: var(--bg-main); color: var(--text-main); font-size: 14px; min-height: 100vh; display: flex; flex-direction: column; }
header { background: var(--bg-card); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
.logo-box { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 16px; }
.logo-badge { background: var(--accent); color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }
nav { display: flex; gap: 8px; flex-wrap: wrap; }
.tab-btn { background: transparent; border: 1px solid transparent; color: var(--text-muted); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 500; transition: all 0.15s ease; }
.tab-btn:hover { color: var(--text-main); background: var(--bg-card-sub); }
.tab-btn.active { color: #fff; background: var(--accent); border-color: var(--accent-hover); }
main { flex: 1; padding: 24px; max-width: 1200px; width: 100%; margin: 0 auto; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
.card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border); }
.card-title { font-size: 15px; font-weight: 600; color: var(--text-main); }
.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px; }
.stat-pill { background: var(--bg-card-sub); border: 1px solid var(--border); border-radius: 6px; padding: 14px; }
.stat-label { font-size: 12px; color: var(--text-muted); margin-bottom: 4px; }
.stat-value { font-size: 22px; font-weight: 700; color: var(--text-main); }
.progress-bar-bg { width: 100%; height: 6px; background: var(--border); border-radius: 3px; margin-top: 8px; overflow: hidden; }
.progress-bar-fill { height: 100%; background: var(--accent); border-radius: 3px; transition: width 0.3s ease; }
table { width: 100%; border-collapse: collapse; text-align: left; }
th, td { padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 13px; }
th { color: var(--text-muted); font-weight: 500; }
tr:hover td { background: var(--bg-card-sub); }
.btn { background: var(--bg-card-sub); border: 1px solid var(--border); color: var(--text-main); padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; font-weight: 500; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 4px; }
.btn:hover { background: var(--border); }
.btn-primary { background: var(--accent); border-color: var(--accent-hover); color: #fff; }
.btn-primary:hover { background: var(--accent-hover); }
.btn-danger { background: rgba(239, 68, 68, 0.15); border-color: var(--danger); color: var(--danger); }
.btn-danger:hover { background: var(--danger); color: #fff; }
.badge { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.badge-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); }
.badge-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid var(--danger); }
.badge-muted { background: var(--bg-card-sub); color: var(--text-muted); border: 1px solid var(--border); }
.input { background: var(--bg-card-sub); border: 1px solid var(--border); color: var(--text-main); padding: 8px 12px; border-radius: 4px; font-size: 13px; outline: none; }
.input:focus { border-color: var(--accent); }
.toast { position: fixed; bottom: 20px; right: 20px; padding: 10px 16px; border-radius: 6px; font-size: 13px; font-weight: 500; color: #fff; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.5); opacity: 0; transform: translateY(10px); transition: all 0.2s ease; }
.toast.show { opacity: 1; transform: translateY(0); }
.toast-success { background: var(--success); }
.toast-error { background: var(--danger); }
.tab-content { display: none; }
.tab-content.active { display: block; }
.modal { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.7); z-index: 500; align-items: center; justify-content: center; }
.modal.show { display: flex; }
.modal-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; width: 90%; max-width: 480px; padding: 24px; }
.modal-title { font-size: 16px; font-weight: 600; margin-bottom: 16px; }
.field-group { margin-bottom: 14px; }
.field-label { display: block; font-size: 12px; color: var(--text-muted); margin-bottom: 6px; }
</style>
</head>
<body>
<header>
  <div class="logo-box">
    <span>Qoder Hub</span>
    <span class="logo-badge">Pro Stack</span>
  </div>
  <nav>
    <button class="tab-btn active" onclick="switchTab('pool')">账号与积分</button>
    <button class="tab-btn" onclick="switchTab('models')">模型与改写</button>
    <button class="tab-btn" onclick="switchTab('scheduler')">签到调度</button>
    <button class="tab-btn" onclick="switchTab('keys')">API Keys</button>
    <button class="tab-btn" onclick="switchTab('security')">安全设置</button>
  </nav>
  <button class="btn btn-danger" onclick="logout()">退出</button>
</header>

<main>
  <!-- TAB: Pool -->
  <div id="tab-pool" class="tab-content active">
    <div class="stats-grid" id="pool-stats">
      <div class="stat-pill">
        <div class="stat-label">剩余 Credits</div>
        <div class="stat-value" id="val-remain">-</div>
      </div>
      <div class="stat-pill">
        <div class="stat-label">已消耗 Credits</div>
        <div class="stat-value" id="val-used">-</div>
      </div>
      <div class="stat-pill">
        <div class="stat-label">可用账号数</div>
        <div class="stat-value" id="val-accounts">-</div>
      </div>
      <div class="stat-pill">
        <div class="stat-label">总可用占比</div>
        <div class="stat-value" id="val-pct">-%</div>
        <div class="progress-bar-bg"><div class="progress-bar-fill" id="val-pct-bar" style="width:0%"></div></div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">Qoder 账号池</div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" onclick="startOAuth()">+ 添加账号 (OAuth)</button>
          <button class="btn" onclick="manualCheckin()">立即一键签到</button>
          <button class="btn" onclick="refreshPool()">刷新</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>UID</th>
            <th>名称</th>
            <th>Realm</th>
            <th>剩余 Credits</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="accounts-tbody"></tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-header">
        <div class="card-title">最近请求记录 (Recent Usage)</div>
        <button class="btn" onclick="loadRecentUsage()">刷新记录</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>时间</th>
            <th>账号</th>
            <th>模型</th>
            <th>Tokens (Prompt/Cached/Out)</th>
            <th>Cache率</th>
            <th>消耗 Credits</th>
          </tr>
        </thead>
        <tbody id="usage-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- TAB: Models -->
  <div id="tab-models" class="tab-content">
    <div class="card">
      <div class="card-header">
        <div class="card-title">模型改写与屏蔽设置</div>
        <div style="display:flex;align-items:center;gap:12px">
          <label style="font-size:13px;color:var(--text-muted)">Context Length 覆盖:</label>
          <input type="number" id="ctx-override-input" class="input" style="width:140px" placeholder="例: 360000">
          <button class="btn btn-primary" onclick="saveModelFilters()">保存配置</button>
        </div>
      </div>
      <p style="color:var(--text-muted);font-size:13px;margin-bottom:14px">
        勾选“屏蔽”将阻止该模型在 /v1/models 显示，并在调用时直接拦截返回 404。Context Length 覆盖将重写 context_length 与 max_input_tokens。
      </p>
      <table>
        <thead>
          <tr>
            <th style="width:80px">屏蔽</th>
            <th>模型 ID</th>
            <th>倍率 (Rate)</th>
            <th>上游 Context</th>
            <th>别名</th>
          </tr>
        </thead>
        <tbody id="models-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- TAB: Scheduler -->
  <div id="tab-scheduler" class="tab-content">
    <div class="card">
      <div class="card-header">
        <div class="card-title">签到保活调度器</div>
        <button class="btn btn-primary" onclick="saveSchedule()">保存调度策略</button>
      </div>
      <div class="field-group">
        <label><input type="checkbox" id="sched-enabled"> 启用自动定时签到</label>
      </div>
      <div class="field-group">
        <label class="field-label">执行时点 (逗号分隔，格式 HH:MM，如 10:05, 21:30)</label>
        <input type="text" id="sched-times" class="input" style="width:100%" placeholder="10:05, 21:30">
      </div>
      <div class="field-group">
        <label class="field-label">防风控随机抖动 (Jitter 范围: 0-30 分钟)</label>
        <input type="number" id="sched-jitter" class="input" style="width:140px" min="0" max="30">
      </div>
      <div style="margin-top:20px;padding:14px;background:var(--bg-card-sub);border-radius:6px;border:1px solid var(--border)">
        <div><strong>下次预计运行:</strong> <span id="sched-next">-</span></div>
        <div style="margin-top:6px"><strong>上次执行时间:</strong> <span id="sched-last-fired">-</span></div>
        <div style="margin-top:6px"><strong>上次执行状态:</strong> <span id="sched-last-status">-</span></div>
      </div>
    </div>
  </div>

  <!-- TAB: Keys -->
  <div id="tab-keys" class="tab-content">
    <div class="card">
      <div class="card-header">
        <div class="card-title">多租户 API Keys</div>
        <div style="display:flex;gap:8px">
          <input type="text" id="new-key-name" class="input" placeholder="Key 备注名称 (例: Claude Code)">
          <button class="btn btn-primary" onclick="addKey()">+ 生成新 Key</button>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>名称</th>
            <th>Key (点击复制)</th>
            <th>创建时间</th>
            <th>状态</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody id="keys-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- TAB: Security -->
  <div id="tab-security" class="tab-content">
    <div class="card" style="max-width:500px">
      <div class="card-header">
        <div class="card-title">控制台密码管理</div>
      </div>
      <div class="field-group">
        <label class="field-label">原密码</label>
        <input type="password" id="old-pass" class="input" style="width:100%">
      </div>
      <div class="field-group">
        <label class="field-label">新密码 (至少 8 位)</label>
        <input type="password" id="new-pass" class="input" style="width:100%">
      </div>
      <button class="btn btn-primary" onclick="updatePassword()">更新密码并同步</button>
    </div>
  </div>
</main>

<div id="toast" class="toast"></div>

<!-- OAuth Modal -->
<div id="oauth-modal" class="modal">
  <div class="modal-box">
    <div class="modal-title">添加 Qoder 账号 (OAuth)</div>
    <p style="color:var(--text-muted);font-size:13px;margin-bottom:14px">请在外部浏览器打开如下链接完成登录授权：</p>
    <div style="margin-bottom:14px">
      <input type="text" id="oauth-url" class="input" style="width:100%" readonly>
    </div>
    <div style="display:flex;gap:8px;margin-bottom:14px">
      <button class="btn btn-primary" onclick="copyOAuthUrl()">复制链接</button>
      <a id="oauth-link" class="btn" href="#" target="_blank">直接打开</a>
    </div>
    <div style="font-size:13px;color:var(--warning)" id="oauth-status">等待授权中...</div>
    <div style="margin-top:16px;text-align:right">
      <button class="btn" onclick="closeOAuth()">取消</button>
    </div>
  </div>
</div>

<script>
let currentTab = 'pool';
let oauthPollTimer = null;
let currentOAuthState = null;

function showToast(msg, isError) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (isError ? 'toast-error' : 'toast-success');
  setTimeout(() => { t.className = 'toast'; }, 3000);
}

function switchTab(name) {
  currentTab = name;
  document.querySelectorAll('.tab-btn').forEach((b, idx) => {
    b.classList.toggle('active', b.getAttribute('onclick').includes(name));
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === 'tab-' + name);
  });
  if (name === 'pool') { refreshPool(); loadRecentUsage(); }
  else if (name === 'models') { loadModels(); }
  else if (name === 'scheduler') { loadSchedule(); }
  else if (name === 'keys') { loadKeys(); }
}

async function api(path, method='GET', body=null) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch('/api' + path, opts);
  if (res.status === 401) {
    window.location.reload();
    return null;
  }
  return await res.json();
}

async function refreshPool() {
  const d = await api('/qoder/pool');
  if (!d || !d.ok) return;
  document.getElementById('val-remain').textContent = d.totals.remain.toLocaleString();
  document.getElementById('val-used').textContent = d.totals.used.toLocaleString();
  document.getElementById('val-accounts').textContent = d.totals.accounts;
  document.getElementById('val-pct').textContent = d.totals.pct + '%';
  document.getElementById('val-pct-bar').style.width = Math.min(100, d.totals.pct) + '%';

  const tbody = document.getElementById('accounts-tbody');
  tbody.innerHTML = '';
  (d.accounts || []).forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><code>${a.uid.slice(0, 10)}...</code></td>
      <td><strong>${a.nickname}</strong></td>
      <td><span class="badge badge-muted">${a.realm || 'cn'}</span></td>
      <td>${a.remain.toLocaleString()}</td>
      <td><span class="badge ${a.enabled ? 'badge-success' : 'badge-danger'}">${a.enabled ? '启用' : '禁用'}</span></td>
      <td>
        <button class="btn" onclick="toggleAccount('${a.uid}', '${a.enabled ? 'disable' : 'enable'}')">${a.enabled ? '停用' : '启用'}</button>
        <button class="btn" onclick="refreshAccount('${a.uid}')">刷新</button>
        <button class="btn btn-danger" onclick="deleteAccount('${a.uid}')">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadRecentUsage() {
  const d = await api('/qoder/recent');
  if (!d || !d.ok) return;
  const tbody = document.getElementById('usage-tbody');
  tbody.innerHTML = '';
  (d.records || []).slice(0, 50).forEach(r => {
    const tr = document.createElement('tr');
    const cacheRate = r.cache_hit_rate != null ? (r.cache_hit_rate * 100).toFixed(1) + '%' : '-';
    tr.innerHTML = `
      <td style="color:var(--text-muted)">${r.at.replace('T', ' ').slice(5, 19)}</td>
      <td>${r.nickname || r.uid}</td>
      <td><code>${r.model}</code></td>
      <td>${r.input_tokens} / ${r.cached_input_tokens || 0} / ${r.output_tokens}</td>
      <td>${cacheRate}</td>
      <td>${r.credits != null ? r.credits : '-'}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function toggleAccount(uid, act) {
  const res = await api('/qoder/account', 'POST', { uid, action: act });
  if (res && res.ok) { showToast('账号状态已更新'); refreshPool(); }
  else showToast(res ? res.error : '操作失败', true);
}

async function refreshAccount(uid) {
  showToast('正在请求上游刷新账号...');
  const res = await api('/qoder/account', 'POST', { uid, action: 'refresh' });
  if (res && res.ok) { showToast('账号已刷新'); refreshPool(); }
  else showToast(res ? res.error : '刷新失败', true);
}

async function deleteAccount(uid) {
  if (!confirm('确认删除该账号？')) return;
  const res = await api('/qoder/account', 'POST', { uid, action: 'delete' });
  if (res && res.ok) { showToast('账号已删除'); refreshPool(); }
  else showToast(res ? res.error : '删除失败', true);
}

async function manualCheckin() {
  showToast('正在触发一键签到...');
  const res = await api('/qoder/checkin', 'POST', {});
  if (res && res.ok) { showToast('签到执行完毕'); refreshPool(); }
  else showToast(res ? res.error : '签到异常', true);
}

async function startOAuth() {
  const res = await api('/qoder/login/start', 'POST', { realm: 'cn' });
  if (!res || !res.ok) { showToast('发起 OAuth 失败', true); return; }
  currentOAuthState = res.state;
  document.getElementById('oauth-url').value = res.auth_url;
  document.getElementById('oauth-link').href = res.auth_url;
  document.getElementById('oauth-modal').classList.add('show');
  document.getElementById('oauth-status').textContent = '等待浏览器中授权...';

  if (oauthPollTimer) clearInterval(oauthPollTimer);
  oauthPollTimer = setInterval(async () => {
    const poll = await api('/qoder/login/poll?state=' + encodeURIComponent(currentOAuthState));
    if (poll && poll.success) {
      clearInterval(oauthPollTimer);
      showToast('账号授权成功！');
      closeOAuth();
      refreshPool();
    }
  }, 3000);
}

function closeOAuth() {
  if (oauthPollTimer) clearInterval(oauthPollTimer);
  document.getElementById('oauth-modal').classList.remove('show');
}

function copyOAuthUrl() {
  const inp = document.getElementById('oauth-url');
  inp.select();
  document.execCommand('copy');
  showToast('授权链接已复制');
}

async function loadModels() {
  const d = await api('/qoder/models');
  if (!d || !d.ok) return;
  document.getElementById('ctx-override-input').value = d.context_override || '';
  const tbody = document.getElementById('models-tbody');
  tbody.innerHTML = '';
  (d.models || []).forEach(m => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><input type="checkbox" class="model-block-chk" data-mid="${m.id}" ${m.blocked ? 'checked' : ''}></td>
      <td><strong>${m.id}</strong></td>
      <td>${m.rate_text}</td>
      <td>${m.context_length ? m.context_length.toLocaleString() : '-'}</td>
      <td style="color:var(--text-muted)">${(m.aliases || []).join(', ') || '-'}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function saveModelFilters() {
  const chks = document.querySelectorAll('.model-block-chk');
  const blocked = [];
  chks.forEach(c => { if (c.checked) blocked.push(c.getAttribute('data-mid')); });
  const ctx = document.getElementById('ctx-override-input').value;
  const res = await api('/qoder/blocked-models', 'POST', {
    models: blocked,
    context_length: ctx ? parseInt(ctx) : null
  });
  if (res && res.ok) showToast('模型改写与屏蔽已保存');
  else showToast('保存失败', true);
}

async function loadSchedule() {
  const d = await api('/qoder/schedule');
  if (!d || !d.ok) return;
  document.getElementById('sched-enabled').checked = d.enabled;
  document.getElementById('sched-times').value = (d.times || []).join(', ');
  document.getElementById('sched-jitter').value = d.jitter_minutes || 0;
  document.getElementById('sched-next').textContent = d.next_run || '未启用';
  document.getElementById('sched-last-fired').textContent = d.last_fired || '无记录';
  const st = document.getElementById('sched-last-status');
  if (d.last_ok === true) { st.textContent = '成功'; st.style.color = 'var(--success)'; }
  else if (d.last_ok === false) { st.textContent = '失败: ' + (d.last_error || ''); st.style.color = 'var(--danger)'; }
  else { st.textContent = '未触发'; st.style.color = 'var(--text-muted)'; }
}

async function saveSchedule() {
  const enabled = document.getElementById('sched-enabled').checked;
  const rawTimes = document.getElementById('sched-times').value.split(',').map(s => s.trim()).filter(Boolean);
  const jitter = parseInt(document.getElementById('sched-jitter').value) || 0;
  const res = await api('/qoder/schedule', 'POST', { enabled, times: rawTimes, jitter_minutes: jitter });
  if (res && res.ok) { showToast('签到调度配置已保存'); loadSchedule(); }
  else showToast(res ? res.error : '保存失败', true);
}

async function loadKeys() {
  const d = await api('/keys');
  if (!d || !d.keys) return;
  const tbody = document.getElementById('keys-tbody');
  tbody.innerHTML = '';
  d.keys.forEach(k => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${k.name}</td>
      <td><code style="cursor:pointer" onclick="copyKey('${k.key}')" title="点击复制">${k.key.slice(0, 10)}...${k.key.slice(-4)}</code></td>
      <td style="color:var(--text-muted)">${new Date(k.created_at * 1000).toLocaleString()}</td>
      <td><span class="badge ${k.enabled ? 'badge-success' : 'badge-danger'}">${k.enabled ? '启用' : '禁用'}</span></td>
      <td>
        <button class="btn" onclick="toggleKey('${k.id}')">${k.enabled ? '停用' : '启用'}</button>
        <button class="btn btn-danger" onclick="deleteKey('${k.id}')">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  });
}

function copyKey(k) {
  navigator.clipboard.writeText(k);
  showToast('API Key 已复制到剪贴板');
}

async function addKey() {
  const name = document.getElementById('new-key-name').value;
  const res = await api('/keys', 'POST', { name });
  if (res && res.key) {
    document.getElementById('new-key-name').value = '';
    showToast('生成新 Key 成功');
    copyKey(res.key);
    loadKeys();
  } else showToast('生成 Key 失败', true);
}

async function toggleKey(id) {
  const res = await api('/keys/toggle', 'POST', { id });
  if (res && res.ok) { showToast('Key 状态已切换'); loadKeys(); }
  else showToast('操作失败', true);
}

async function deleteKey(id) {
  if (!confirm('确认删除该 API Key？删除后客户端将立刻无法访问。')) return;
  const res = await api('/keys/delete', 'POST', { id });
  if (res && res.ok) { showToast('Key 已删除'); loadKeys(); }
  else showToast('删除失败', true);
}

async function updatePassword() {
  const old_password = document.getElementById('old-pass').value;
  const new_password = document.getElementById('new-pass').value;
  const res = await api('/password', 'POST', { old_password, new_password });
  if (res && res.ok) {
    document.getElementById('old-pass').value = '';
    document.getElementById('new-pass').value = '';
    showToast('密码更新成功');
  } else showToast(res ? res.error : '更新失败', true);
}

async function logout() {
  await api('/logout', 'POST', {});
  window.location.reload();
}

window.onload = () => { switchTab('pool'); };
</script>
</body>
</html>
"""

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 - Qoder API Control</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
body { background: #111113; color: #f4f4f5; display: flex; align-items: center; justify-content: center; height: 100vh; }
.box { background: #18181b; border: 1px solid #2e2e36; border-radius: 8px; width: 100%; max-width: 360px; padding: 28px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); }
.title { font-size: 18px; font-weight: 600; margin-bottom: 20px; text-align: center; }
.field { margin-bottom: 16px; }
.label { display: block; font-size: 12px; color: #a1a1aa; margin-bottom: 6px; }
.input { width: 100%; background: #222227; border: 1px solid #2e2e36; color: #fff; padding: 10px 12px; border-radius: 4px; font-size: 14px; outline: none; }
.input:focus { border-color: #7c3aed; }
.btn { width: 100%; background: #7c3aed; border: none; color: #fff; padding: 10px; border-radius: 4px; font-size: 14px; font-weight: 600; cursor: pointer; transition: background 0.2s; }
.btn:hover { background: #6d28d9; }
.error { color: #ef4444; font-size: 13px; margin-top: 10px; text-align: center; }
</style>
</head>
<body>
<div class="box">
  <div class="title">Qoder API 控制台</div>
  <form method="POST" action="/login">
    <div class="field">
      <label class="label">管理密码</label>
      <input type="password" name="password" class="input" required autofocus>
    </div>
    <button type="submit" class="btn">登录</button>
    __ERROR__
  </form>
</div>
</body>
</html>
"""


# --- HTTP Request Handler & Server

class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        return

    def _send_json(self, status, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, status, html_str, cookie=None):
        raw = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _read_body_json(self):
        val = self.headers.get("Content-Length")
        if not val:
            return {}
        try:
            length = int(val)
            raw = self.rfile.read(length)
            return json.loads(raw.decode("utf-8", "ignore"))
        except Exception:
            return {}

    def _is_authenticated(self):
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:].strip()
            if validate_session(token) or verify_admin_password(token):
                return True

        cookie_hdr = self.headers.get("Cookie")
        if cookie_hdr:
            c = SimpleCookie()
            try:
                c.load(cookie_hdr)
                if "qoder_session" in c:
                    tok = c["qoder_session"].value
                    if validate_session(tok):
                        return True
            except Exception:
                pass
        return False

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if path == "/healthz":
            self._send_json(200, {"ok": True, "service": "qoder-admin", "version": VERSION})
            return

        if path == "/login":
            self._send_html(200, LOGIN_HTML.replace("__ERROR__", ""))
            return

        if not self._is_authenticated():
            if path.startswith("/api/"):
                self._send_json(401, {"ok": False, "error": "Unauthorized"})
            else:
                self._send_html(200, LOGIN_HTML.replace("__ERROR__", ""))
            return

        if path in ("/", "/index.html"):
            self._send_html(200, UI_HTML)
            return

        # API Routes
        try:
            if path == "/api/qoder/pool":
                self._send_json(200, qoder_pool())
            elif path == "/api/qoder/usage":
                self._send_json(200, qoder_usage())
            elif path == "/api/qoder/recent":
                limit = int(query.get("limit", [100])[0])
                self._send_json(200, qoder_recent_usage(limit))
            elif path == "/api/qoder/models":
                self._send_json(200, qoder_model_rows())
            elif path == "/api/qoder/blocked-models":
                self._send_json(200, qoder_blocked_models_conf())
            elif path == "/api/qoder/schedule":
                self._send_json(200, qoder_schedule_info())
            elif path == "/api/qoder/login/poll":
                state = query.get("state", [""])[0]
                self._send_json(200, qoder_login_poll(state))
            elif path == "/api/keys":
                self._send_json(200, load_keys())
            else:
                self._send_json(404, {"ok": False, "error": "Endpoint not found"})
        except Exception as e:
            self._send_json(500, {"ok": False, "error": str(e)})

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/login":
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length).decode("utf-8", "ignore")
            form = parse_qs(raw)
            pw = form.get("password", [""])[0]
            if verify_admin_password(pw):
                tok = create_session()
                cookie = f"qoder_session={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"
                self.send_response(302)
                self.send_header("Set-Cookie", cookie)
                self.send_header("Location", "/")
                self.end_headers()
            else:
                err = '<div class="error">密码不正确</div>'
                self._send_html(200, LOGIN_HTML.replace("__ERROR__", err))
            return

        if not self._is_authenticated():
            self._send_json(401, {"ok": False, "error": "Unauthorized"})
            return

        body = self._read_body_json()

        try:
            if path == "/api/logout":
                cookie = "qoder_session=; Path=/; HttpOnly; Max-Age=0"
                self._send_json(200, {"ok": True})
            elif path == "/api/qoder/checkin":
                res = qoder_checkin()
                self._send_json(200, {"ok": True, "result": res})
            elif path == "/api/qoder/credits/refresh":
                res = qoder_credits_refresh()
                self._send_json(200, {"ok": True, "result": res})
            elif path == "/api/qoder/login/start":
                realm = body.get("realm", "cn")
                self._send_json(200, qoder_login_start(realm))
            elif path == "/api/qoder/login/cancel":
                state = body.get("state", "")
                self._send_json(200, qoder_login_cancel(state))
            elif path == "/api/qoder/account":
                uid = body.get("uid")
                act = body.get("action")
                self._send_json(200, {"ok": True, "result": qoder_account_action(uid, act)})
            elif path == "/api/qoder/blocked-models":
                res = save_qoder_blocked_models(body.get("models"), body.get("context_length"))
                self._send_json(200, {"ok": True, "config": res})
            elif path == "/api/qoder/schedule":
                res = save_qoder_schedule(body.get("enabled"), body.get("times"), body.get("jitter_minutes", 5))
                self._send_json(200, {"ok": True, "config": res})
            elif path == "/api/keys":
                name = body.get("name", "")
                self._send_json(200, create_key(name))
            elif path == "/api/keys/toggle":
                key_id = body.get("id")
                self._send_json(200, toggle_key(key_id))
            elif path == "/api/keys/delete":
                key_id = body.get("id")
                self._send_json(200, delete_key(key_id))
            elif path == "/api/password":
                ok, msg = change_admin_password(body.get("old_password"), body.get("new_password"))
                self._send_json(200 if ok else 400, {"ok": ok, "error" if not ok else "message": msg})
            else:
                self._send_json(404, {"ok": False, "error": "Endpoint not found"})
        except Exception as e:
            self._send_json(500, {"ok": False, "error": str(e)})


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, max_workers=24):
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="qoder-admin")
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


def start_background_admin(host=None, port=None):
    addr = (host or LISTEN[0], int(port or LISTEN[1]))
    srv = BoundedThreadingHTTPServer(addr, AdminHandler)
    t = threading.Thread(target=srv.serve_forever, name="qoder-admin-server", daemon=True)
    t.start()
    return srv, t


def main():
    print(f"Starting qoder-admin on {LISTEN[0]}:{LISTEN[1]}")
    start_qoder_scheduler()
    BoundedThreadingHTTPServer(LISTEN, AdminHandler).serve_forever()


if __name__ == "__main__":
    main()
