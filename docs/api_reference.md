# BehaveGuard API Reference

BehaveGuard exposes a FastAPI application on **`http://localhost:8888`**. It
provides a REST API under `/api/v1`, a Prometheus metrics endpoint, and a
real-time WebSocket alert stream at `/ws/alerts`.

Source: [`behaveguard/api/`](../behaveguard/api/).

---

## Authentication

Every `/api/v1` route **except** `GET /api/v1/health`, and the `/ws/alerts`
WebSocket, requires a **Bearer token**.

- The token is taken from the `BEHAVEGUARD_API_TOKEN` environment variable. If
  that variable is unset, a random 32-hex-character token is generated at startup
  (printed/managed by the daemon).
- REST clients send it in the `Authorization` header:
  `Authorization: Bearer <token>`.
- WebSocket clients send it as the `token` **query parameter** (browsers cannot
  set WebSocket headers): `/ws/alerts?token=<token>`.
- An invalid or missing token yields **401 Unauthorized**
  (`{"detail": "missing or invalid bearer token"}`). The WebSocket is closed with
  code **1008** (policy violation).

Token comparison uses `secrets.compare_digest` (constant-time).

Set the token for a session:

```bash
export BEHAVEGUARD_API_TOKEN="$(openssl rand -hex 16)"
export TOKEN="$BEHAVEGUARD_API_TOKEN"   # convenience for the examples below
```

## Rate limiting

A lightweight in-memory limiter caps each **client IP** to **100 requests per
60-second rolling window** (across all routes, including health). Exceeding it
returns **429 Too Many Requests** (`{"detail": "rate limit exceeded"}`).

## Conventions

- Base URL in examples: `http://localhost:8888`.
- All request/response bodies are JSON unless noted (`/metrics` is plain text).
- Timestamps named `*_ns` are monotonic kernel nanoseconds; `*_unix` are wall-clock
  Unix seconds.

---

## Endpoint summary

| Method | Path | Auth | Description |
|--------|------|:----:|-------------|
| `GET` | `/api/v1/health` | no | Liveness: `{status, version, uptime}`. |
| `GET` | `/api/v1/health/metrics` | yes | Prometheus metrics (text). |
| `GET` | `/api/v1/processes` | yes | List monitored processes. |
| `GET` | `/api/v1/processes/{pid}` | yes | Process detail + score history. |
| `GET` | `/api/v1/processes/{pid}/events` | yes | Recent stored events for a PID. |
| `GET` | `/api/v1/alerts` | yes | List alerts (filterable). |
| `GET` | `/api/v1/alerts/{alert_id}` | yes | One alert with its explanation. |
| `POST` | `/api/v1/alerts/{alert_id}/acknowledge` | yes | Acknowledge an alert. |
| `POST` | `/api/v1/alerts/suppress` | yes | Add a suppression rule. |
| `POST` | `/api/v1/models/train` | yes | Start a background training job. |
| `GET` | `/api/v1/models/status` | yes | Status of all training jobs. |
| `GET` | `/api/v1/models/list` | yes | List trained model bundles. |
| `DELETE` | `/api/v1/models/{process_name}` | yes | Delete a model bundle. |
| `WS` | `/ws/alerts?token=…` | yes | Real-time alert stream. |

---

## Health & metrics

### `GET /api/v1/health`

Unauthenticated liveness probe for orchestrators.

Response `200`:

```json
{ "status": "ok", "version": "1.0.0", "uptime_seconds": 12.345 }
```

```bash
curl -s http://localhost:8888/api/v1/health
```

### `GET /api/v1/health/metrics`

Prometheus exposition format covering uptime and the alert funnel
(deduplicated / rate-limited / routed counters from the alert manager).

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/health/metrics
```

Sample output:

```
# HELP behaveguard_uptime_seconds Process uptime in seconds.
# TYPE behaveguard_uptime_seconds gauge
behaveguard_uptime_seconds 12.345
# TYPE behaveguard_alerts_emitted counter
behaveguard_alerts_emitted 7
```

---

## Processes

### `GET /api/v1/processes`

List processes seen by the live collector. Returns an empty list when no
collector is attached (e.g. off-Linux or daemon not running) rather than erroring.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/processes
```

Response `200`:

```json
{
  "processes": [
    { "pid": 4242, "comm": "nginx", "event_count": 1875,
      "last_seen_ns": 1000000812345, "latest_score": 12.0, "latest_severity": "LOW" }
  ],
  "total": 1
}
```

### `GET /api/v1/processes/{pid}`

Per-process detail including recorded anomaly-score history.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/processes/4242
```

Response `200`:

```json
{
  "pid": 4242,
  "comm": "nginx",
  "event_count": 1875,
  "score_history": [
    { "timestamp_ns": 1000000800000, "score": 12.0, "severity": "LOW" },
    { "timestamp_ns": 1000030800000, "score": 88.5, "severity": "CRITICAL" }
  ]
}
```

### `GET /api/v1/processes/{pid}/events`

Most recent stored events for a process. Query parameter `limit`
(default `1000`, range `1..10000`).

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8888/api/v1/processes/4242/events?limit=50"
```

Response `200`:

```json
{
  "pid": 4242,
  "events": [
    { "timestamp_ns": 1000000800000, "event_type": 1, "pid": 4242,
      "comm": "nginx", "detail": { "syscall_name": "openat", "ret": 7 } }
  ],
  "total": 1
}
```

`event_type` follows the `EventType` enum: `1`=syscall, `2`=network, `3`=file,
`4`=process, `5`=injection, `6`=container_escape, `7`=lolbin, `8`=antiforensic,
`9`=dns_tunnel.

---

## Alerts

### `GET /api/v1/alerts`

List alerts with optional filters. Query parameters:

| Param | Type | Default | Notes |
|-------|------|---------|-------|
| `severity` | string | — | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`. |
| `process_name` | string | — | Exact process name. |
| `acknowledged` | bool | — | Filter by ack state. |
| `limit` | int | `100` | `1..1000`. |
| `offset` | int | `0` | Pagination offset. |

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8888/api/v1/alerts?severity=CRITICAL&limit=20"
```

Response `200`:

```json
{
  "alerts": [
    {
      "alert_id": 101,
      "process_name": "nginx",
      "pid": 4242,
      "score": 88.5,
      "severity": "CRITICAL",
      "explanation": "Process injection detected (process_vm_writev into pid 1337); LOLBin execution: nc.",
      "timestamp_ns": 1000030800000,
      "acknowledged": false,
      "created_unix": 1718900000.0
    }
  ],
  "total": 1,
  "unacknowledged": 1
}
```

### `GET /api/v1/alerts/{alert_id}`

Fetch one alert (including its full explanation). `404` if not found.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/alerts/101
```

### `POST /api/v1/alerts/{alert_id}/acknowledge`

Acknowledge an alert, optionally with a note. `404` if not found.

Request body (`AcknowledgeRequest`):

```json
{ "note": "investigated — confirmed deploy script, benign" }
```

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"note": "investigated — benign deploy"}' \
  http://localhost:8888/api/v1/alerts/101/acknowledge
```

Response `200`: `{ "status": "acknowledged", "detail": "alert 101" }`

### `POST /api/v1/alerts/suppress`

Add a suppression rule so future alerts for a process below a score threshold are
filtered (for tuning out known false positives).

Request body (`SuppressRequest`):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `process_name` | string | — | required |
| `reason` | string | — | required |
| `max_score_suppress` | float | `100.0` | `0..100`; suppress alerts at or below this score. |
| `expires_at` | string | `null` | ISO-8601; `422` if malformed. |
| `created_by` | string | `"user"` | audit attribution. |

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "process_name": "backup-agent",
        "reason": "nightly cron spikes file activity",
        "max_score_suppress": 75.0,
        "expires_at": "2026-12-31T00:00:00",
        "created_by": "secops"
      }' \
  http://localhost:8888/api/v1/alerts/suppress
```

Response `200`: `{ "status": "suppressed", "detail": "backup-agent" }`

---

## Models

### `POST /api/v1/models/train`

Start a **background** training job that builds a per-process baseline (LSTM +
VAE). Returns immediately with a `job_id`; poll `/models/status` for progress.

Request body (`TrainRequest`):

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `process_name` | string | — | required |
| `observation_minutes` | int | `60` | `1..1440` minutes to observe normal behavior. |

```bash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"process_name": "nginx", "observation_minutes": 120}' \
  http://localhost:8888/api/v1/models/train
```

Response `200`: `{ "job_id": "a1b2c3d4e5f6a7b8", "process_name": "nginx", "state": "queued" }`

### `GET /api/v1/models/status`

Status of all known training jobs (`queued` / `running` / `completed` / `failed`).

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/models/status
```

Response `200`:

```json
{
  "jobs": [
    { "job_id": "a1b2c3d4e5f6a7b8", "process_name": "nginx", "state": "completed",
      "detail": "trained: nginx", "started_unix": 1718900000.0,
      "finished_unix": 1718907200.0 }
  ]
}
```

### `GET /api/v1/models/list`

List trained model bundles known to the model store
(`~/.behaveguard/models/<process>/`).

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/models/list
```

Response `200`:

```json
{
  "models": [
    { "process_name": "nginx",
      "metadata": { "process_name": "nginx", "input_dim": 427, "trained_unix": 1718907200.0 } }
  ],
  "total": 1
}
```

### `DELETE /api/v1/models/{process_name}`

Delete a model bundle. `404` if no model exists for the process.

```bash
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:8888/api/v1/models/nginx
```

Response `200`: `{ "status": "deleted", "process_name": "nginx" }`

---

## WebSocket: `/ws/alerts`

A real-time push stream of alerts as they are emitted by the alert manager.

- **Auth:** supply the Bearer token as the `token` query parameter. The socket is
  accepted only after the token validates; otherwise it is closed with code
  **1008**.
- **Direction:** server → client. Each message is one alert serialized as JSON
  (the same shape as `AlertOut` above).
- **Lifecycle:** the connection subscribes to the alert manager on accept and
  unsubscribes on disconnect.

Example with [`websocat`](https://github.com/vi/websocat):

```bash
websocat "ws://localhost:8888/ws/alerts?token=$TOKEN"
```

Each received frame looks like:

```json
{
  "alert_id": 102,
  "process_name": "sshd",
  "pid": 991,
  "score": 93.0,
  "severity": "CRITICAL",
  "explanation": "Anti-forensic action: log_deletion under /var/log/auth.log; namespace_change_count elevated.",
  "timestamp_ns": 1000061200000,
  "acknowledged": false,
  "created_unix": 1718900061.0
}
```

Browser client sketch:

```javascript
const token = "<your token>";
const ws = new WebSocket(`ws://localhost:8888/ws/alerts?token=${token}`);
ws.onmessage = (e) => {
  const alert = JSON.parse(e.data);
  console.log(`[${alert.severity}] ${alert.process_name} (pid ${alert.pid}): ${alert.explanation}`);
};
```

---

## Error responses

| Status | When | Body |
|-------:|------|------|
| `401` | Missing/invalid Bearer token on a protected route. | `{"detail": "missing or invalid bearer token"}` |
| `404` | Unknown `alert_id` or model `process_name`. | `{"detail": "..."}` |
| `422` | Malformed body / query (e.g. bad `expires_at`, out-of-range `limit`). | FastAPI validation error. |
| `429` | Rate limit exceeded (100/min per IP). | `{"detail": "rate limit exceeded"}` |

See [`architecture.md`](architecture.md) for where the API sits in the pipeline
and [`ml_models.md`](ml_models.md) for how scores and explanations are produced.
