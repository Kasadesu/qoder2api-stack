# Qoder2API Stack

An independent, production-grade reverse proxy, dynamic model rewriting layer, and administration console dedicated to [qoder2api-hub](https://github.com/shuishuipingan/qoder2api-hub).

```
                 +---------------------------------------------+
                 |       Client Applications / SDKs            |
                 +----------------------+----------------------+
                                        | (Bearer sk-qd-...)
                                        v
                 +---------------------------------------------+
                 |       Caddy / TLS Gateway (Port 443)        |
                 +----------+-----------------------+----------+
                            |                       |
           (Path: /*)       |                       | (Path: /admin/*)
                            v                       v
            +-------------------------------+ +-------------------------------+
            |  qoder-model-filter.py (8791) | |     qoder-admin.py (8792)     |
            | - Multi-tenant Key Check      | | - Obsidian Dark Web Console   |
            | - Model Catalog Rewriting     | | - Account & Credits Pool      |
            | - Fast Model Snooping (<64KB) | | - Dynamic Scheduler + Jitter  |
            | - HTTP Keep-Alive Pool        | | - Key Management & Security   |
            +---------------+---------------+ +---------------+---------------+
                            |                                 |
                            +----------------+----------------+
                                             |
                                             v
                            +---------------------------------+
                            |  qoder2api-hub Docker (8790)    |
                            |  Upstream Qoder Gateway Engine  |
                            +---------------------------------+
```

---

## Key Features

1. **Zero-Copy Stream Pass-Through & Connection Pooling**
   - Built-in `_UpstreamPool` maintaining persistent HTTP Keep-Alive connections.
   - Non-blocking, zero-copy chunked streaming relay for low time-to-first-token (TTFT).
2. **Dynamic Model Catalog Rewriting & Strict 404 Interception**
   - Rewrites `/v1/models` in-flight: strips unwanted models and overrides upstream `context_length` / `max_input_tokens` (e.g. 180K -> 360K) to eliminate client-side token truncation.
   - Intercepts requests referencing blocked models (including cached aliases) and immediately responds with 404 `model_not_found` before hitting upstream.
3. **Multi-tenant API Key Authentication & Fail-Closed Defense**
   - High-throughput key verification with nanosecond `stat` caching and automatic hot-reload.
   - Strict Fail-Closed policy: returns OpenAI-compatible 401 schemas upon missing or invalid keys.
4. **Obsidian-Themed Administration Console**
   - Single-file, zero-dependency console running on Python 3 standard library.
   - Full management over Qoder account pool, OAuth login, credits quotas, and per-request audit logs (`/usage/recent`).
5. **Anti-Fingerprinting Auto Check-in Daemon**
   - Background scheduler supporting multiple execution points (e.g. `10:05`, `21:30`).
   - Configurable jitter randomization window (0-30 mins) to prevent coordinated cloud anti-bot triggers.

---

## Directory Structure

```
qoder2api-stack/
├── qoder-model-filter.py       # Core proxy & filtering middleware (port 8791)
├── qoder-admin.py              # Web console & automation daemon (port 8792)
├── qoder-config.example.json   # Template for gateway credentials (qoder.json)
├── blocked-models.example.json # Template for blocked model list & context override
├── qoder-schedule.example.json # Template for check-in schedule & jitter
├── Caddyfile.example           # Production reverse proxy configuration
├── deploy/
│   ├── docker-compose.yml      # Official qoder2api-hub container deployment
│   ├── qoder-filter.service    # Systemd service unit for filter middleware
│   └── qoder-admin.service     # Systemd service unit for admin console
└── tools/
    ├── test-qoder-filter.py    # Unit & end-to-end integration test suite
    ├── test-qoder-admin.py     # Admin API & key management test suite
    └── test-qoder-schedule.py  # Scheduler & jitter logic test suite
```

---

## Environment Variables

### `qoder-model-filter.py`

| Variable | Default | Description |
| :--- | :--- | :--- |
| `QODER_UPSTREAM` | `http://127.0.0.1:8790` | Upstream `qoder2api-hub` service URL |
| `QODER_HOST` | `127.0.0.1` | Local bind host |
| `QODER_PORT` | `8791` | Local listen port |
| `QODER_CONFIG_FILE` | `/opt/qoder2api/blocked-models.json` | Path to model blocking & context override JSON |
| `QODER_KEYS_FILE` | `/opt/qoder2api/admin/keys.json` | Path to valid client API keys store |
| `QODER_KEY_CHECK` | `1` | Enable multi-tenant key validation (`1` or `0`) |
| `QODER_API_KEY_FILE`| `/opt/qoder2api/.apikey` | Optional upstream internal token file |

### `qoder-admin.py`

| Variable | Default | Description |
| :--- | :--- | :--- |
| `QODER_ADMIN_HOST` | `127.0.0.1` | Console listen host |
| `QODER_ADMIN_PORT` | `8792` | Console listen port |
| `QODER_ADMIN_DIR` | `/opt/qoder2api/admin` | State storage directory for credentials and keys |
| `QODER_CFG_FILE` | `/opt/qoder2api/admin/qoder.json` | Upstream connection credentials config |
| `QODER_BLOCK_FILE` | `/opt/qoder2api/blocked-models.json` | Model filter JSON path |
| `QODER_SCHEDULE_FILE` | `/opt/qoder2api/admin/qoder-schedule.json` | Check-in scheduler configuration |
| `CADDY_FILE` | `/etc/caddy/Caddyfile` | Optional path to Caddyfile for password hash sync |

---

## Quick Start & Deployment

### 1. Launch Upstream Container
```bash
cd deploy
docker compose up -d
```

### 2. Configure Credentials
Copy configuration templates to your working admin directory:
```bash
mkdir -p /opt/qoder2api/admin
cp qoder-config.example.json /opt/qoder2api/admin/qoder.json
cp blocked-models.example.json /opt/qoder2api/blocked-models.json
cp qoder-schedule.example.json /opt/qoder2api/admin/qoder-schedule.json
```
Edit `/opt/qoder2api/admin/qoder.json` and configure `panel_password` to match your `qoder2api-hub` instance.

### 3. Deploy Systemd Services
```bash
cp deploy/qoder-filter.service /etc/systemd/system/
cp deploy/qoder-admin.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now qoder-filter.service qoder-admin.service
```

### 4. Setup Caddy Ingress
Incorporate `Caddyfile.example` into your `/etc/caddy/Caddyfile` and run `caddy reload`.

---

## Running the Automated Test Suites

The stack includes comprehensive, self-contained test suites without external Python dependencies:

```bash
# Test proxy middleware, model rewriting, and key authentication
python tools/test-qoder-filter.py

# Test admin control panel APIs, CRUD operations, and session security
python tools/test-qoder-admin.py

# Test schedule normalization, timestamps, and jitter logic
python tools/test-qoder-schedule.py
```
