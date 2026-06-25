# BehaveGuard 🛡️

> Runtime behavioral anomaly detection for Linux — powered by eBPF and Machine Learning.

[![CI](https://img.shields.io/github/actions/workflow/status/urrra39/BehaveGuard/ci.yml?branch=develop&style=flat-square)](https://github.com/urrra39/BehaveGuard/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg?style=flat-square)](https://www.python.org/)
[![Linux 5.15+](https://img.shields.io/badge/linux-5.15%2B-orange.svg?style=flat-square)](https://www.kernel.org/)
[![Stars](https://img.shields.io/github/stars/urrra39/BehaveGuard?style=flat-square)](https://github.com/urrra39/BehaveGuard/stargazers)

## Abstract

Signature-based defenses answer the question *"does this code match known
malware?"* and are therefore structurally blind to novel threats. **BehaveGuard**
reframes detection as a behavioral anomaly problem: it instruments every process
on a Linux host with eBPF, learns a per-process model of *normal* behavior from
an observation period, and flags statistically significant deviations in real
time. Each monitored process is summarized every 30 seconds into a **427-dimension
feature vector** spanning system-call frequency and n-gram structure, network
connection graphs, file-access patterns, process-tree dynamics, and five
purpose-built threat layers (process injection, container escape,
living-off-the-land binaries, anti-forensics, and DNS tunneling). An ensemble of
an LSTM sequence autoencoder and a variational autoencoder produces a calibrated
0–100 anomaly score; a SHAP-style explainer renders each verdict in plain
language. The detector catches zero-day behavior — credential dumping, reverse
shells, lateral movement — that signature engines miss, while remaining
explainable and operator-tunable.

## Why behavioral detection?

A Python web server *normally* opens files under `/var/www/`, makes outbound
HTTPS connections, and reads its config. If it suddenly reads `/etc/shadow`,
connects to a foreign IP on port 4444, and spawns a shell — that is a breach,
**even if the malware has never been seen before.** Signatures cannot express
"this process is doing things it never does." BehaveGuard can.

## Architecture

```
┌──────────────────────── Linux Kernel (eBPF) ────────────────────────┐
│  9 BCC programs on kprobes / tracepoints / LSM hooks                 │
│  syscall · network · file · process                                 │
│  injection · container-escape · lolbin · anti-forensic · dns-tunnel │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │  ring buffers
┌───────────────────────────────▼─────────────────────────────────────┐
│                         User space (Python)                          │
│  Collector ─▶ Feature Extractor (427-dim) ─▶ Ensemble (LSTM + VAE)   │
│      │                                              │                 │
│      ▼                                              ▼                 │
│  Event Store (SQLite)                       Anomaly Scorer (0–100)    │
│                                                     │                 │
│                              Explainer ◀────────────┤                 │
│                                                     ▼                 │
│  Dashboard (Dash) ◀── REST API + WS ◀──────── Alert Manager ──▶ Channels
│       :8050                  :8888              dedup/suppress   webhook/email/syslog
└──────────────────────────────────────────────────────────────────────┘
```

The feature/scoring/storage/alert layers are **pure-Python and import without
torch, numpy, or BCC** (heavy dependencies are imported lazily), which keeps the
codebase testable on any platform. See [`docs/architecture.md`](docs/architecture.md).

### Feature vector (427 dimensions)

| Block | Dims | Examples |
|---|---|---|
| Syscall frequency | 335 | per-syscall relative frequency |
| Syscall bigrams | 50 | hashed consecutive-syscall pairs |
| Network | 10 | unique IPs/ports, byte rates, Tor port, RFC1918, **DNS size/rate/max** |
| File | 7 | files in system dirs, path entropy, **log deletions, timestamp tampering** |
| Process | 22 | shell spawn, priv-esc, **injection target, namespace change, pivot_root, 15× LOLBin** |
| Temporal | 3 | window duration, events/sec, activity duty cycle |

## Threat model & detection matrix

| Threat | eBPF layer / signal | Feature(s) | MITRE ATT&CK |
|---|---|---|---|
| Credential dumping | file reads of `/etc/shadow`, `/root/.ssh` | `files_in_system_dirs` | T1003 |
| Reverse shell | shell exec + outbound to odd port | `is_shell_spawned`, network rate | T1059 / T1571 |
| Lateral movement | connections to RFC1918 + `ssh` exec | `is_connecting_to_rfc1918` | T1021 |
| Data exfiltration | mass reads + large egress | `bytes_sent_per_second` | T1041 |
| Privilege escalation | `setuid`/`ptrace` + memory writes | `privilege_escalation_attempt`, `is_injection_target` | T1068 / T1055 |
| Process injection | `security_ptrace`, `process_vm_writev`, `/proc/<pid>/mem` | `is_injection_target` | T1055 |
| Container escape | `setns` / `unshare` / `pivot_root` | `namespace_change_count`, `pivot_root_attempt` | T1611 |
| LOLBin abuse | exec watchlist (wget/curl/nc/…) | `lolbin_*` one-hot | T1218 |
| Anti-forensics | `unlink`/`utimensat`/`truncate` on `/var/log` | `log_deletion_count`, `timestamp_modification_count` | T1070 |
| DNS tunneling | oversized UDP/53 queries | `max_dns_payload_bytes`, `dns_query_rate` | T1048 / T1071.004 |

### The five advanced defense layers (mechanics · kernel hooks · mitigation)

| Pillar | Mechanics | Kernel hook(s) | Feature(s) | Mitigation vector |
|---|---|---|---|---|
| **Process injection** | One process writes another's memory to run under a trusted identity, evading per-process baselines | `security_ptrace_access_check` (LSM, ATTACH-only), `process_vm_writev`, `mem_write` (`/proc/<pid>/mem`) | `is_injection_target` | Quarantine injector; `kernel.yama.ptrace_scope=2`; seccomp-deny `process_vm_writev` |
| **Container escape** | A container manipulates namespaces to break isolation and reach the host | `setns`, `unshare`, `pivot_root` | `namespace_change_count`, `pivot_root_attempt` | Drop `CAP_SYS_ADMIN`; seccomp-deny namespace syscalls; user namespaces; read-only rootfs |
| **LOLBin abuse** | Signed, legitimate binaries (wget/curl/nc/…) fetch & run payloads — no malware to sign | `sched_process_exec` + 16-entry watchlist | `lolbin_execution_count`, 15× `lolbin_<bin>` | Execution allowlist (fapolicyd/SELinux); remove unneeded interpreters; egress filtering |
| **Anti-forensics** | Deleting/truncating logs and timestomping to erase evidence & break timelines | `security_inode_unlink`, `truncate`, `utimensat` (→ `/var/log`) | `log_deletion_count`, `timestamp_modification_count` | Append-only/immutable logs (`chattr +a`); remote syslog forwarding; auditd; FIM |
| **DNS tunneling** | C2/exfil encoded in oversized DNS queries to bypass port-53-trusting firewalls | `udp_sendmsg` → `:53`, payload > 100 B | `avg_dns_query_size`, `dns_query_rate`, `max_dns_payload_bytes` | Force a controlled resolver; block direct `:53` egress; query size/rate limits; DoH inspection |

Every layer self-filters BehaveGuard's own PID (`-DOWN_PID`) and is loaded
defensively (a kernel missing a hook disables only that layer). Full design notes:
[`docs/architecture.md` §5](docs/architecture.md). Each pillar has an isolated
simulation and assertion in `tests/simulations/` and `tests/unit/test_features.py`.

## Quick start

```bash
# 1. install (Linux, as root) — pulls BCC + the package
sudo bash scripts/install_deps.sh

# 2. initialize, then learn "normal" for ~60 minutes
sudo behaveguard init
sudo behaveguard train --duration 60

# 3. run (collector + scorer + alerts + API + dashboard)
sudo behaveguard run
#  🌐 Dashboard: http://localhost:8050   🔌 API: http://localhost:8888
```

## Requirements

- **Linux 5.15+** (eBPF ring buffers, LSM hooks)
- **Python 3.10+**
- **root** (required to load eBPF programs — see [SECURITY.md](SECURITY.md) for why this is safe)

## CLI reference

| Command | Description |
|---|---|
| `behaveguard init` | Check eBPF support, init storage, mint an API token |
| `behaveguard train --duration 60 [--process nginx]` | Learn baselines from live "normal" activity |
| `behaveguard run [--no-dashboard]` | Start monitoring (collector + API + dashboard) |
| `behaveguard status` | Trained models and unacknowledged alert counts |
| `behaveguard alerts --last 1h [--severity HIGH]` | List recent alerts |
| `behaveguard explain --pid 1234` | Explain why a process looks suspicious |
| `behaveguard whitelist add --pid 1234 \| --process backup` | Suppress known-good processes |

## API reference

All `/api/v1` routes require a Bearer token (minted on `init`); `/api/v1/health`
is public. Rate limit: 100 requests/min/IP. See [`docs/api_reference.md`](docs/api_reference.md).

```bash
TOKEN=$(cat ~/.behaveguard/api_token)

curl http://localhost:8888/api/v1/health
# {"status":"ok","version":"1.0.0","uptime_seconds": …}

curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/alerts
curl -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/processes
curl -H "Authorization: Bearer $TOKEN" -X POST \
     http://localhost:8888/api/v1/alerts/suppress \
     -d '{"process_name":"backup","reason":"noisy","max_score_suppress":60}'
```

Real-time alert stream (WebSocket): `ws://localhost:8888/ws/alerts?token=$TOKEN`.

## Training your own baselines

`behaveguard train` observes live processes for the given window, assumes that
period is benign, and fits a per-process bundle (LSTM + VAE + normalizer +
threshold) saved under `~/.behaveguard/models/<process>/`. Retrain a single
process with `--process nginx`. See [`docs/ml_models.md`](docs/ml_models.md).

## Performance

- Feature extraction is pure-Python and processes **thousands of windows/second**
  on a single core (`python scripts/benchmark.py`).
- The eBPF programs self-filter the collector's own PID and use ring buffers for
  low-overhead kernel→user transfer; back-pressure drops-and-counts rather than
  blocking the kernel producer.
- Storage is SQLite (WAL) with retention rotation; models are small (`<` a few MB
  per process).

## Comparison

| | BehaveGuard | Falco | OSSEC | Snort |
|---|---|---|---|---|
| Detection model | **behavioral ML (per-process)** | rules | log/HIDS rules | network signatures |
| Catches zero-day behavior | ✅ | partial (rules) | ❌ | ❌ |
| eBPF kernel instrumentation | ✅ | ✅ | ❌ | ❌ |
| Per-process learned baseline | ✅ | ❌ | ❌ | ❌ |
| Explainable verdicts | ✅ (SHAP-style) | rule name | rule id | signature id |
| Container-escape / injection / DNS-tunnel layers | ✅ | partial | ❌ | partial |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` (lint + typecheck +
tests) before submitting. Report vulnerabilities per [SECURITY.md](SECURITY.md).

## References

1. Gregg, B. *BPF Performance Tools*, Addison-Wesley, 2019.
2. Forrest, S. et al. "A Sense of Self for Unix Processes." *IEEE S&P*, 1996. — system-call anomaly detection.
3. Malhotra, P. et al. "LSTM-based Encoder-Decoder for Multi-sensor Anomaly Detection." *ICML Anomaly Detection Workshop*, 2016.
4. Kingma, D. P. & Welling, M. "Auto-Encoding Variational Bayes." *ICLR*, 2014.
5. Lundberg, S. & Lee, S. "A Unified Approach to Interpreting Model Predictions" (SHAP). *NeurIPS*, 2017.
6. MITRE ATT&CK® — https://attack.mitre.org/

## License

MIT © urrra39
