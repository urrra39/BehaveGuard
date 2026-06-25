# Changelog

All notable changes to BehaveGuard will be documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

## [1.0.0] - 2026-06-26
### Added
- Initial project structure
- eBPF-based process monitoring (syscall, network, file, process events)
- LSTM + VAE ensemble anomaly detection
- FastAPI REST server with WebSocket streaming
- Real-time Dash dashboard
- Docker support
- Full test suite

#### Advanced defense layers (5 new enterprise-grade eBPF detectors)
- **Process injection detection** (`injection_monitor.c`) — hooks the
  `security_ptrace_access_check` LSM, `process_vm_writev`, and `/proc/<pid>/mem`
  writes to catch one process hijacking another's memory. New `InjectionEvent`
  and the `is_injection_target` feature.
- **Container escape detection** (`container_escape_monitor.c`) — hooks `setns`,
  `unshare`, and `pivot_root` to catch namespace breakout. New
  `ContainerEscapeEvent` and the `namespace_change_count` /
  `pivot_root_attempt` features.
- **LOLBin abuse detection** (`lolbin_monitor.c`) — hooks `sched_process_exec`
  and matches a watchlist (wget, curl, python, perl, bash, nc, ncat, socat,
  base64, xxd, dd, crontab, at, systemctl, chmod). New `LolbinEvent`,
  `lolbin_execution_count`, and per-binary one-hot `lolbin_*` features.
- **Anti-forensic detection** (`antiforensic_monitor.c`) — hooks
  `security_inode_unlink`, `utimensat`, and `truncate` filtered to `/var/log`
  to catch log clearing and timestomping. New `AntiforensicEvent` and the
  `log_deletion_count` / `timestamp_modification_count` features.
- **DNS tunneling detection** (`dns_tunnel_monitor.c`) — hooks `udp_sendmsg`
  on port 53 for oversized (> 100 byte) queries. New `DnsTunnelEvent` and the
  `avg_dns_query_size` / `dns_query_rate` / `max_dns_payload_bytes` features.
- Feature vector grew from 403 to **427 dimensions**; the SHAP-style explainer
  now gives these layers decisive salience and names them explicitly
  ("Process Injection Target", "Container Escape Attempt", "DNS Tunneling
  Exfiltration"). The eBPF collector loads every layer defensively so a kernel
  missing a hook degrades gracefully instead of failing.
