# Qoder2API Stack

Reverse proxy, model rewriting layer, and administration console for [qoder2api-hub](https://github.com/shuishuipingan/qoder2api-hub).

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
            | - Multi-tenant Key Check      | | - Web Admin Console           |
            | - Model Catalog Rewriting     | | - Account & Credits Pool      |
            | - Fast Model Snooping (<64KB) | | - Check-in Scheduler + Jitter |
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

## Features

- **Model Filtering & Rewriting**: Rewrites `/v1/models` in-flight, overrides upstream `context_length` / `max_input_tokens`, and rejects blocked models with 404 before hitting upstream.
- **Connection Pooling & Stream Relay**: Persistent HTTP Keep-Alive connection pool (`_UpstreamPool`) with non-blocking chunked streaming pass-through.
- **Multi-Tenant Key Authentication**: Sub-millisecond key verification with mtime caching, hot-reload, and fail-closed defense.
- **Admin Console**: Web UI for managing Qoder accounts, OAuth authorization, credits quotas, and per-request usage metrics.
- **Check-in Scheduler**: Background daemon supporting configurable schedule times and random jitter delay to prevent fixed-time bot detection.

---

## Directory Structure

```
qoder2api-stack/
├── qoder-model-filter.py       # Reverse proxy and model filter (port 8791)
├── qoder-admin.py              # Web console and scheduler daemon (port 8792)
├── qoder-config.example.json   # Template for upstream credentials (qoder.json)
├── blocked-models.example.json # Template for blocked models and context length override
├── qoder-schedule.example.json # Template for check-in schedule and jitter
├── Caddyfile.example           # Reverse proxy configuration template
├── deploy/
│   ├── docker-compose.yml      # Official qoder2api-hub container deployment
│   ├── qoder-filter.service    # Systemd unit for filter middleware
│   └── qoder-admin.service     # Systemd unit for admin console
└── tools/
    ├── test-qoder-filter.py    # Filter unit and integration tests
    ├── test-qoder-admin.py     # Admin API and key management tests
    └── test-qoder-schedule.py  # Scheduler and jitter tests
```

---

## Environment Variables

### `qoder-model-filter.py`

| Variable | Default | Description |
| :--- | :--- | :--- |
| `QODER_UPSTREAM` | `http://127.0.0.1:8790` | Upstream `qoder2api-hub` service URL |
| `QODER_HOST` | `127.0.0.1` | Local bind host |
| `QODER_PORT` | `8791` | Local listen port |
| `QODER_CONFIG_FILE` | `/opt/qoder2api/blocked-models.json` | Path to model filter configuration |
| `QODER_KEYS_FILE` | `/opt/qoder2api/admin/keys.json` | Path to valid API keys store |
| `QODER_KEY_CHECK` | `1` | Enable multi-tenant key validation (`1` or `0`) |
| `QODER_API_KEY_FILE`| `/opt/qoder2api/.apikey` | Optional upstream internal token file |

### `qoder-admin.py`

| Variable | Default | Description |
| :--- | :--- | :--- |
| `QODER_ADMIN_HOST` | `127.0.0.1` | Console listen host |
| `QODER_ADMIN_PORT` | `8792` | Console listen port |
| `QODER_ADMIN_DIR` | `/opt/qoder2api/admin` | Storage directory for credentials and keys |
| `QODER_CFG_FILE` | `/opt/qoder2api/admin/qoder.json` | Upstream connection configuration |
| `QODER_BLOCK_FILE` | `/opt/qoder2api/blocked-models.json` | Model filter configuration path |
| `QODER_SCHEDULE_FILE` | `/opt/qoder2api/admin/qoder-schedule.json` | Check-in scheduler configuration |
| `CADDY_FILE` | `/etc/caddy/Caddyfile` | Optional path to Caddyfile for password hash sync |

---

## Quick Start

### 1. Launch Upstream Container
```bash
cd deploy
docker compose up -d
```

### 2. Configure Credentials
```bash
mkdir -p /opt/qoder2api/admin
cp qoder-config.example.json /opt/qoder2api/admin/qoder.json
cp blocked-models.example.json /opt/qoder2api/blocked-models.json
cp qoder-schedule.example.json /opt/qoder2api/admin/qoder-schedule.json
```
Edit `/opt/qoder2api/admin/qoder.json` and set `panel_password` to match your `qoder2api-hub` container.

### 3. Deploy Systemd Services
```bash
cp deploy/qoder-filter.service /etc/systemd/system/
cp deploy/qoder-admin.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now qoder-filter.service qoder-admin.service
```

### 4. Setup Caddy
Incorporate `Caddyfile.example` into your `/etc/caddy/Caddyfile` and run `caddy reload`.

---

## Testing

```bash
python tools/test-qoder-filter.py
python tools/test-qoder-admin.py
python tools/test-qoder-schedule.py
```
