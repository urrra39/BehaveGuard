# BehaveGuard Architecture

BehaveGuard is a runtime **behavioral** anomaly detector for Linux. Instead of
matching signatures of known-bad code, it learns what *normal* looks like for
every process on a host and raises an alert when a process starts behaving
abnormally. This is what makes it effective against zero-day exploits, fileless
malware, and living-off-the-land attacks that have no signature to match.

The system observes the kernel with eBPF, turns raw kernel events into compact
numeric **feature vectors**, scores those vectors with an **LSTM + VAE ensemble**
trained per process, and routes anything anomalous to alert channels, a
dashboard, and an API.

---

## 1. System overview

```
                         ┌──────────────────────────────────────────────┐
                         │                   KERNEL                      │
                         │                                               │
   syscalls, sockets,    │   ┌────────────────────────────────────────┐ │
   file ops, exec,       │   │  9 eBPF / BCC programs (per hook)       │ │
   ptrace, setns, ...  ──┼──▶│  syscall · network · file · process     │ │
                         │   │  injection · container_escape · lolbin  │ │
                         │   │  antiforensic · dns_tunnel              │ │
                         │   └───────────────────┬────────────────────┘ │
                         │                       │  fixed-layout C structs│
                         │            BPF_MAP_TYPE_RINGBUF (per program)  │
                         └───────────────────────┼────────────────────────┘
                                                 │  raw bytes
                                                 ▼
   ┌───────────────────────────────────────────────────────────────────────┐
   │                              USERSPACE                                  │
   │                                                                         │
   │  ┌─────────────┐   decode    ┌──────────────┐   30s sliding windows     │
   │  │  Collector  │────────────▶│ event_types  │──────────────┐            │
   │  │ (BCC, lazy) │  ring_buffer│  dataclasses │              │            │
   │  └─────────────┘             └──────────────┘              ▼            │
   │                                              ┌────────────────────────┐ │
   │                                              │   Feature Extractor    │ │
   │                                              │  427-dim vector        │ │
   │                                              │  (pure Python)         │ │
   │                                              └───────────┬────────────┘ │
   │                                                          │ vector        │
   │                                                          ▼               │
   │                                              ┌────────────────────────┐ │
   │                                              │     ML Ensemble        │ │
   │                                              │  LSTM autoencoder      │ │
   │                                              │  + VAE  (per process)  │ │
   │                                              └───────────┬────────────┘ │
   │                                                          │ recon errors  │
   │                                                          ▼               │
   │                                              ┌────────────────────────┐ │
   │                                              │    Anomaly Scorer      │ │
   │                                              │  ensemble → 0..100     │ │
   │                                              │  + per-PID context     │ │
   │                                              │  + safe-PID suppress   │ │
   │                                              │  + Explainer           │ │
   │                                              └───────────┬────────────┘ │
   │                                                          │ AnomalyScore  │
   │                                                          ▼               │
   │                                              ┌────────────────────────┐ │
   │                                              │     Alert Manager      │ │
   │                                              │ dedup · rate-limit ·   │ │
   │                                              │ rules · routing        │ │
   │                                              └───┬───────┬────────┬───┘ │
   │                                                  │       │        │     │
   │                          ┌───────────────────────┘       │        └───┐ │
   │                          ▼                               ▼            ▼ │
   │                 ┌─────────────────┐          ┌────────────────┐  ┌──────────┐
   │                 │  Channels       │          │  REST + WS API │  │ Dashboard│
   │                 │ webhook/email/  │          │  FastAPI :8888 │  │  Dash    │
   │                 │ syslog          │          │  /ws/alerts    │  │  :8050   │
   │                 └─────────────────┘          └────────────────┘  └──────────┘
   │                                                                         │
   │  Storage (SQLite, asyncio): event_store · alert_store · model_registry  │
   └───────────────────────────────────────────────────────────────────────┘
```

The pipeline is strictly one-directional: **kernel events flow up, alerts flow
out.** Each stage has a single responsibility and a typed contract with its
neighbours, which is what allows the lower layers to be tested in isolation
without a kernel, without numpy, and without torch.

---

## 2. Component responsibilities

| Stage | Module | Responsibility |
|-------|--------|----------------|
| eBPF probes | `behaveguard/collector/programs/*.c` | Attach to kernel hooks, filter to the events of interest, and write fixed-layout C structs into a per-program ring buffer. Self-filter BehaveGuard's own PID. |
| Ring buffer bridge | `collector/ring_buffer.py` | Bridge the synchronous BCC ring-buffer callback world into `asyncio`, so events become an awaitable stream. |
| Collector | `collector/ebpf_collector.py` | Compile each program with `-DOWN_PID=<our pid>`, load it **defensively** (per-program `try/except`), and decode raw bytes into typed dataclasses. |
| Event model | `collector/event_types.py` | Single source of truth for the wire format: `*Raw` ctypes structs (byte-for-byte kernel layout) and decoded `@dataclass` events. Stdlib only. |
| Feature extractor | `features/extractor.py` (+ `syscall/network/file/process_features.py`, `window.py`, `normalizer.py`) | Turn one 30-second window of mixed events into a single 427-dim feature vector in `[0, 1]`. Pure Python. |
| ML models | `models/lstm_detector.py`, `models/autoencoder.py`, `models/ensemble.py` | Per-process LSTM sequence autoencoder + single-window VAE; reconstruction error → anomaly signal. Weighted ensemble. |
| Thresholds & training | `models/threshold_tuner.py`, `models/baseline_builder.py`, `models/model_store.py` | Learn per-process baselines, tune thresholds (mean + n·σ, FPR-bounded, ROC-AUC), persist model bundles. |
| Anomaly scorer | `scoring/anomaly_scorer.py`, `scoring/severity.py`, `scoring/explainer.py` | Combine ensemble output with per-PID sequence context, suppress known-safe PIDs, map to a 0–100 score + severity, and explain *which defense layer* fired. |
| Alert manager | `alerts/alert_manager.py`, `alerts/rules_engine.py`, `alerts/channels/*` | Deduplicate, rate-limit, apply suppression rules, fan out to channels, and feed WebSocket subscribers. |
| Storage | `storage/event_store.py`, `storage/alert_store.py`, `storage/model_registry.py` | Durable history of events and alerts (SQLite via `asyncio.to_thread`) and an atomic-JSON model registry. |
| API | `api/server.py`, `api/routers/*`, `api/schemas.py` | FastAPI app at `:8888`: REST under `/api/v1`, Prometheus metrics, and a `/ws/alerts` WebSocket. Bearer-token auth + 100/min rate limit. |
| Dashboard | Dash app at `:8050` | Live operator view, refreshed every 5 seconds. |
| CLI | `behaveguard` (click) | `init`, `train`, `run`, `status`, `alerts`, `explain`, `whitelist`. |

---

## 3. Data and event lifecycle

A single anomaly is produced by the following lifecycle:

1. **Capture (kernel).** A process makes a syscall / opens a socket / execs a
   binary / writes another process's memory. The relevant eBPF program's hook
   fires. If the acting PID is BehaveGuard's own (`OWN_PID`), the event is
   dropped in-kernel. Otherwise the program writes a fixed-layout struct into its
   ring buffer.

2. **Decode (collector).** `ebpf_collector.py` reads raw bytes from each ring
   buffer and reconstructs a typed dataclass (`SyscallEvent`, `NetworkEvent`,
   `FileEvent`, `ProcessEvent`, `InjectionEvent`, `ContainerEscapeEvent`,
   `LolbinEvent`, `AntiforensicEvent`, `DnsTunnelEvent`) via each class's
   `from_raw`.

3. **Window (features).** Events are grouped into **30-second sliding windows**
   per process. When a window is ready, `FeatureExtractor.extract_vector()`
   produces a 427-dim feature vector. This is the pipeline's hot path and is
   pure Python (see `scripts/benchmark.py` for its throughput).

4. **Score (ML).** The vector (and a short sequence of recent vectors, for the
   LSTM) is fed to the process's model bundle. The LSTM autoencoder and the VAE
   each emit a reconstruction error; the `EnsembleDetector` weights them into a
   single signal, which the `ThresholdTuner` calibration maps to **0–100**.

5. **Contextualize (scoring).** `AnomalyScorer` blends the ensemble score with
   per-PID sequence context, suppresses **known-safe PIDs** (whitelist), assigns
   a `Severity` (LOW / MEDIUM / HIGH / CRITICAL), and asks the `Explainer` to
   name the top contributing features — explicitly calling out advanced defense
   layers (injection, container escape, LOLBin, anti-forensic, DNS tunnel) when
   they drive the score.

6. **Alert (alerts).** The resulting `Alert` is deduplicated and rate-limited by
   `AlertManager`, checked against suppression rules, then fanned out to
   configured **channels** (webhook / email / syslog), pushed to **WebSocket**
   subscribers, and persisted in `alert_store`.

7. **Observe (API / dashboard).** Operators read alerts and process state via the
   REST API (`/api/v1/...`), the Prometheus `/metrics` endpoint, the real-time
   `/ws/alerts` stream, or the Dash dashboard at `:8050`.

**Training** is the same path run in reverse intent: during `behaveguard train`,
windows are collected as *normal* behavior and handed to `BaselineBuilder`, which
fits the per-process LSTM + VAE, tunes thresholds, and writes a model bundle to
`~/.behaveguard/models/<process>/`.

---

## 4. The 427-dimension feature vector

Every window becomes a vector of exactly **427** features, all squashed to
`[0, 1]` (counts are normalized; boolean signals stay 0/1). The ordering is fixed
and assembled from the sub-extractors so the names and the vector can never drift
out of sync (`FeatureExtractor.FEATURE_NAMES`).

| Block | Dims | Contents |
|-------|-----:|----------|
| **Syscall** | **385** | 335 per-syscall **frequency** slots (one per x86_64 syscall number `0..334`, sized to `max(SYSCALL_NAMES)+1` so even `execveat`=322 is covered) **+ 50 hashed syscall bigrams** (sequence n-grams folded into 50 buckets with a fixed, `PYTHONHASHSEED`-independent polynomial hash for reproducibility). |
| **Network** | **10** | Connection/transfer aggregates including outbound/inbound counts and byte volume, plus DNS statistics: **average**, **rate**, and **max DNS** payload signals derived from the DNS-tunnel layer. |
| **File** | **7** | File-operation aggregates plus the anti-forensic signals **`log_deletion`** and **`timestamp_mod`** (deletes/timestomps/truncations under `/var/log`). |
| **Process** | **22** | 3 base signals (`child_processes_spawned`, `is_shell_spawned`, `privilege_escalation_attempt`) + 4 advanced signals (`is_injection_target`, `namespace_change_count`, `pivot_root_attempt`, `lolbin_execution_count`) + **15 LOLBin one-hot** flags (`lolbin_<binary>` for the watchlist). |
| **Temporal** | **3** | `window_duration_ms`, `events_per_second`, `cpu_time_ratio` (a 100 ms-bucket activity duty cycle). |
| **Total** | **427** | |

> The syscall block is reported as a single 385-dim group (335 frequency + 50
> bigram) because the bigrams are computed from, and stored alongside, the
> frequency slots. `FeatureExtractor.NUM_FEATURES` is computed dynamically, and
> the ML models read `input_dim = FeatureExtractor.NUM_FEATURES`, so the vector,
> the model input shape, and this table stay in agreement automatically.

---

## 5. Advanced defense layers — mechanics, kernel hooks, and mitigation

Beyond the four foundational collectors (syscall / network / file / process),
BehaveGuard ships five purpose-built layers targeting high-impact, evasion-heavy
techniques. Each is a standalone eBPF program emitting a dedicated event that maps
to dedicated feature(s); each is covered by an isolated simulation in
`tests/simulations/simulate_attack.py` and asserted in `tests/simulations/test_detection.py`.

### 5.1 Process injection — `injection_monitor.c`
- **Mechanics.** An attacker writes code or data into *another* process's address
  space and executes under that victim's trusted identity, neatly defeating
  per-process baselines by "becoming" a process whose normal profile is benign.
- **Kernel hooks.** `security_ptrace_access_check` (LSM, gated on
  `PTRACE_MODE_ATTACH` so read-only introspection is ignored), the
  `sys_enter_process_vm_writev` tracepoint, and a kprobe on `mem_write` (writes to
  `/proc/<pid>/mem`).
- **Signal → feature.** `InjectionEvent(method, target_pid)` → **`is_injection_target`**.
- **Mitigation vector.** Quarantine/kill the injector (its PID is captured),
  correlate `target_pid`; harden with `kernel.yama.ptrace_scope=2` and a seccomp
  profile denying `process_vm_writev`/`ptrace`. MITRE **T1055**.

### 5.2 Container escape — `container_escape_monitor.c`
- **Mechanics.** A containerized process manipulates namespaces to break isolation
  and reach the host kernel/filesystem.
- **Kernel hooks.** `sys_enter_setns`, `sys_enter_unshare`, `sys_enter_pivot_root`
  tracepoints (the `flags`/`nstype` are captured).
- **Signal → feature.** `ContainerEscapeEvent(action, flags)` →
  **`namespace_change_count`** and **`pivot_root_attempt`**.
- **Mitigation vector.** Drop `CAP_SYS_ADMIN`, deny `setns`/`unshare`/`pivot_root`
  via seccomp, enable user namespaces and a read-only rootfs; on detection,
  terminate the container and audit the host. MITRE **T1611**.

### 5.3 LOLBin abuse — `lolbin_monitor.c`
- **Mechanics.** Living-Off-The-Land binaries (signed, legitimate tools) are abused
  to fetch and run payloads without dropping malware, defeating signature scanners.
- **Kernel hook.** `sched_process_exec` tracepoint, with an in-kernel exact match
  against a 16-entry watchlist (`wget`, `curl`, `python`/`python3`, `perl`, `bash`,
  `nc`, `ncat`, `socat`, `base64`, `xxd`, `dd`, `crontab`, `at`, `systemctl`, `chmod`).
- **Signal → feature.** `LolbinEvent(comm)` → **`lolbin_execution_count`** plus a
  per-binary **`lolbin_<binary>`** one-hot flag.
- **Mitigation vector.** Allowlist execution (fapolicyd / SELinux), remove unneeded
  interpreters, and apply egress filtering; flag the parent process chain. MITRE **T1218**.

### 5.4 Anti-forensics — `antiforensic_monitor.c`
- **Mechanics.** Destroying or truncating logs to erase evidence and *timestomping*
  to defeat timeline analysis.
- **Kernel hooks.** `security_inode_unlink` (LSM, stable across kernels),
  `sys_enter_truncate`, and `sys_enter_utimensat`, all filtered to paths under
  `/var/log`.
- **Signal → feature.** `AntiforensicEvent(action, path)` → **`log_deletion_count`**
  (unlink/truncate) and **`timestamp_modification_count`** (utimensat).
- **Mitigation vector.** Append-only/immutable logs (`chattr +a`), remote syslog
  forwarding, auditd, and file-integrity monitoring so destroyed evidence already
  exists off-host. MITRE **T1070**.

### 5.5 DNS tunneling — `dns_tunnel_monitor.c`
- **Mechanics.** Command-and-control and exfiltration are encoded inside DNS queries
  to slip past firewalls that trust port 53; oversized queries are the tell.
- **Kernel hook.** kprobe on `udp_sendmsg`, resolving the destination from
  `msg->msg_name` (fallback to the socket), emitting **only** when the destination
  port is 53 and the payload exceeds 100 bytes.
- **Signal → feature.** `DnsTunnelEvent(payload_size, daddr)` →
  **`avg_dns_query_size`**, **`dns_query_rate`**, and **`max_dns_payload_bytes`**.
- **Mitigation vector.** Force DNS through a controlled resolver, block direct
  egress on `:53`, enforce query size/rate limits, and inspect DoH; on detection,
  block the destination and isolate the host. MITRE **T1048 / T1071.004**.

Every program self-filters BehaveGuard's own PID (`-DOWN_PID`) and is loaded
defensively by the collector, so a kernel that lacks a given hook degrades to "that
one layer disabled" rather than failing the whole detector.

---

## 6. Import-safety design (lazy `torch` / `numpy` / `bcc`)

A core architectural rule: **the feature, scoring, storage, and alert layers must
import and run with nothing but the Python standard library.** Only the layers
that genuinely need heavy or platform-specific dependencies pull them in, and
they do so **lazily** (inside the function that needs them), never at module
import time.

| Dependency | Imported by | Import strategy |
|------------|-------------|-----------------|
| `bcc` | `collector/ebpf_collector.py`, `ring_buffer.py` | Lazy — imported only when a collector is actually started. Decoding (`event_types.py`) is stdlib-only, so events can be parsed and tested without BCC and on non-Linux hosts. |
| `numpy` | `features/extractor.py` (`.extract()`), `features/normalizer.py` | Lazy — used only as the array container in `extract()`. The hot path `extract_vector()` returns a plain `list[float]` and never touches numpy. |
| `torch` | `models/lstm_detector.py`, `models/autoencoder.py`, `models/ensemble.py`, `models/baseline_builder.py` | Lazy / confined — kept out of the import path of everything else. The API server creates the torch-backed scorer optionally, so the process module and the `/api/v1/health` endpoint import without torch. |

Consequences of this design:

- **Testability.** The pure-Python pipeline (decode → features → score → alert →
  store) is exercised end-to-end on a stock interpreter, which is exactly what
  `scripts/benchmark.py` relies on.
- **Portability.** The package imports cleanly on CPython 3.9.13 (`from __future__
  import annotations` everywhere; `typing.Union` rather than PEP 604 `X | Y` for
  any alias evaluated at runtime), even though the deployment target is Python
  3.10+ on Linux 5.15+.
- **Graceful degradation.** A missing optional dependency (no torch installed, no
  rules file present, an eBPF program that fails to load) is handled locally and
  does not crash the rest of the system.

---

## 7. Runtime requirements

| Requirement | Value | Why |
|-------------|-------|-----|
| Kernel | Linux **5.15+** | eBPF ring buffers and the LSM/tracepoint hooks the programs attach to. |
| Python | **3.10+** (imports clean on 3.9) | Runtime target; the codebase stays 3.9-importable for the pure-Python layers. |
| Privileges | **root** | Loading eBPF programs and attaching kernel probes requires `CAP_BPF` / `CAP_SYS_ADMIN`. |
| API port | `:8888` | FastAPI REST + WebSocket. |
| Dashboard port | `:8050` | Dash operator UI. |
| Model store | `~/.behaveguard/models/` | Per-process model bundles. |

See [`ebpf_programs.md`](ebpf_programs.md) for the kernel-side detail,
[`ml_models.md`](ml_models.md) for the detection models, and
[`api_reference.md`](api_reference.md) for the HTTP/WebSocket surface.
