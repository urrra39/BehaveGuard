# BehaveGuard eBPF Programs

BehaveGuard's eyes into the kernel are **9 eBPF/BCC C programs**, one per
detection concern. They live in
[`behaveguard/collector/programs/`](../behaveguard/collector/programs/) and are
loaded by [`collector/ebpf_collector.py`](../behaveguard/collector/ebpf_collector.py).

Each program attaches to one or more kernel hooks, filters in-kernel to the
events that matter, and writes a **fixed-layout C struct** into a per-program
`BPF_MAP_TYPE_RINGBUF`. Userspace reads the raw bytes back and reconstructs a
typed event via the matching `*Raw` ctypes structure in
[`collector/event_types.py`](../behaveguard/collector/event_types.py). The
ctypes layout and the C struct must agree **byte for byte** — the byte sizes in
the table below are the contract.

---

## 1. Program catalog

The first four programs are the foundational telemetry layers; the last five are
the **advanced defense layers** that target specific high-signal attack
techniques.

| # | File | Kernel hook(s) | Emits (struct) | Bytes | Detects |
|--:|------|----------------|----------------|------:|---------|
| 1 | `syscall_monitor.c` | `raw_syscalls:sys_enter` / `sys_exit` tracepoints | `SyscallEventRaw` | **80** | Every syscall (nr, args[3], ret, comm) — the raw behavioral substrate for the 385-dim syscall feature block. |
| 2 | `network_monitor.c` | socket layer (`tcp_connect` / `udp_sendmsg` and inbound paths) | `NetworkEventRaw` | **56** | TCP/UDP connections and transfers: src/dst IPv4, ports, protocol, direction, byte count. |
| 3 | `file_monitor.c` | VFS open/read/write/unlink path | `FileEventRaw` | **312** | File operations with full path (`PATH_MAX_LEN`=256), flags, byte count, and operation code (open/read/write/unlink). |
| 4 | `process_monitor.c` | `sched:sched_process_exec` / `fork` / `exit` | `ProcessEventRaw` | **560** | Process lifecycle: exec/fork/exit with executable path, command line, ppid, exit code. |
| 5 | `injection_monitor.c` | `security_ptrace_access_check` (LSM), `process_vm_writev`, writes to `/proc/<pid>/mem` | `InjectionEventRaw` | **40** | **Process injection** — one process writing another's memory. `method` ∈ {ptrace, proc_mem, process_vm_writev}; `target_pid` is the victim. |
| 6 | `container_escape_monitor.c` | `setns`, `unshare`, `pivot_root` syscalls | `ContainerEscapeEventRaw` | **40** | **Container / namespace escape** — namespace manipulation. `action` ∈ {setns, unshare, pivot_root}; `flags` carries the nstype/unshare flags. |
| 7 | `lolbin_monitor.c` | `sched:sched_process_exec` with an in-kernel **watchlist** filter | `LolbinEventRaw` | **40** | **Living-Off-The-Land binaries** — execution of watchlisted tools (wget, curl, nc, socat, python, base64, …). Only emits on a watchlist match. |
| 8 | `antiforensic_monitor.c` | `security_inode_unlink` (LSM), `utimensat`, `truncate`, scoped to `/var/log` | `AntiforensicEventRaw` | **296** | **Anti-forensics** — log tampering under `/var/log`. `action` ∈ {unlink, timestomp, truncate}; captures the target `path`. |
| 9 | `dns_tunnel_monitor.c` | `udp_sendmsg` to destination port **53**, payload **> 100** bytes | `DnsTunnelEventRaw` | **48** | **DNS tunneling / exfiltration** — oversized UDP/53 queries. Captures `daddr`, `dport`, and `payload_size`. |

> The byte sizes are exact and were confirmed with
> `ctypes.sizeof(<StructName>Raw)`. They arise from natural alignment: e.g.
> `SyscallEventRaw` = `u64 ts` + `u32 pid` + `u32 tgid` + `u32 uid` + `char[16]
> comm` + `u64 nr` + `u64 ret` + `u64[3] args`, padded to **80** bytes. The two
> large structs (`file`=312, `process`=560) carry 256-byte path/cmdline buffers.

---

## 2. Struct field reference

The decoded dataclasses (consumed by feature extraction) and their raw layouts
are defined together in `event_types.py`. Key fields per family:

- **Syscall (80 B):** `timestamp_ns`, `pid`, `tgid`, `uid`, `comm[16]`,
  `syscall_nr`, `ret`, `args[3]`.
- **Network (56 B):** `timestamp_ns`, `pid`, `uid`, `comm[16]`, `saddr`, `daddr`
  (`__be32`), `sport`, `dport` (host order), `protocol` (6=TCP/17=UDP),
  `direction` (0=out/1=in), `bytes_count`.
- **File (312 B):** `timestamp_ns`, `ret` (signed), `pid`, `uid`, `flags`,
  `bytes_count`, `operation`, `comm[16]`, `path[256]`.
- **Process (560 B):** `timestamp_ns`, `pid`, `ppid`, `uid`, `exit_code`
  (signed), `action`, `comm[16]`, `exe_path[256]`, `cmdline[256]`.
- **Injection (40 B):** `timestamp_ns`, `pid`, `uid`, `target_pid`, `method`,
  `comm[16]`.
- **Container escape (40 B):** `timestamp_ns`, `pid`, `uid`, `action`, `flags`,
  `comm[16]`.
- **LOLBin (40 B):** `timestamp_ns`, `pid`, `ppid`, `uid`, `comm[16]`.
- **Anti-forensic (296 B):** `timestamp_ns`, `pid`, `uid`, `action`, `comm[16]`,
  `path[256]`.
- **DNS tunnel (48 B):** `timestamp_ns`, `pid`, `uid`, `daddr`, `payload_size`,
  `dport`, `comm[16]`.

The `EventType` discriminator assigns stable numeric IDs `1..9` in the order
above (`SYSCALL`=1 … `DNS_TUNNEL`=9).

---

## 3. The `OWN_PID` self-filter

BehaveGuard observes *every* process — which would include **itself**. A detector
that reacted to its own syscalls, its own socket reads from the ring buffer, and
its own model I/O would generate a storm of false positives and could feed back
on itself.

To prevent this, every program is compiled with a `-DOWN_PID=<collector pid>`
macro at load time. Inside each hook, the very first check compares the acting
task's PID against `OWN_PID` and **returns early** (dropping the event in-kernel)
when they match. Filtering in the kernel — before the event is ever written to
the ring buffer — means BehaveGuard's own activity costs essentially nothing and
never reaches userspace.

Because `OWN_PID` is injected at compile time (not read from a map), the check is
a single constant comparison with no map lookup on the hot path.

---

## 4. Ring buffers

Each program owns a dedicated `BPF_MAP_TYPE_RINGBUF`. Ring buffers (Linux 5.8+,
hence the **5.15+** floor) are the modern replacement for perf buffers and give
BehaveGuard:

- **Fixed-layout records.** Programs reserve space, populate the struct in place,
  and submit it. Userspace reads exactly `sizeof(struct)` bytes per record and
  hands them to the matching `*Raw.from_buffer_copy` decode.
- **Ordering and back-pressure.** Records preserve submission order, and a full
  buffer drops new records rather than corrupting the stream.
- **An async bridge.** [`collector/ring_buffer.py`](../behaveguard/collector/ring_buffer.py)
  wraps the synchronous BCC ring-buffer callback into `asyncio`, turning each
  program's buffer into an awaitable event stream that the collector multiplexes.

Per-program isolation means a flood on one layer (say, a syscall-heavy process)
cannot starve another layer (say, an injection event) of buffer space.

---

## 5. Defensive loading

eBPF program loading is inherently environment-sensitive: a given kernel may not
export a particular tracepoint or LSM hook, a symbol may be renamed across
versions, or the BTF/headers may differ. BehaveGuard therefore loads each program
**independently and defensively**.

`ebpf_collector.py`:

1. Compiles each `.c` source with the BCC toolchain, injecting `-DOWN_PID`.
2. Wraps **each program's** compile-and-attach in its own `try/except`.
3. Logs and **skips** any program that fails to load, then continues with the
   rest.

The practical effect: if `antiforensic_monitor.c` cannot attach on a particular
kernel, BehaveGuard still runs with the other eight layers rather than failing to
start. Detection coverage degrades gracefully instead of collapsing. This mirrors
the package-wide import-safety philosophy described in
[`architecture.md`](architecture.md#5-import-safety-design-lazy-torch--numpy--bcc):
a missing capability is handled locally, never fatally.

---

## 6. From kernel struct to feature

The path from a raw struct to a model input:

```
eBPF hook ──▶ ring buffer ──▶ ebpf_collector reads N bytes
          ──▶ <Family>EventRaw.from_buffer_copy(bytes)
          ──▶ <Family>Event.from_raw(raw)        # decoded dataclass
          ──▶ grouped into a 30s window per process
          ──▶ FeatureExtractor.extract_vector()  # 427-dim vector
```

The advanced-layer events feed specific feature dimensions: injection →
`is_injection_target`; container escape → `namespace_change_count` /
`pivot_root_attempt`; LOLBin → `lolbin_execution_count` + the 15 one-hot
`lolbin_<binary>` flags; anti-forensic → `log_deletion` / `timestamp_mod`; DNS
tunnel → the average/rate/max DNS network features. See the feature breakdown in
[`architecture.md`](architecture.md#4-the-427-dimension-feature-vector).
