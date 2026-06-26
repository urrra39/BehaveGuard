"""Attack simulations for BehaveGuard.

:class:`AttackSimulator` produces, per attack vector, a list of raw events that
carry the *exact* signature the feature extractor keys on, so the extracted
feature vector lights up the discriminating feature(s). Vectors covered:

* ``credential_dumping``  — reads of /etc/shadow, /etc/passwd, /root/.ssh/id_rsa
  (``files_in_system_dirs`` elevates).
* ``reverse_shell``       — an interactive ``bash -i`` exec plus an outbound
  connection to a foreign IP on 4444 (``is_shell_spawned`` == 1).
* ``lateral_movement``    — outbound connections to RFC1918 internal hosts plus
  an ``ssh`` exec (``is_connecting_to_rfc1918`` == 1).
* ``data_exfiltration``   — many file reads plus a large outbound transfer
  (``bytes_sent_per_second`` elevates).
* ``privilege_escalation``— setuid(105)/ptrace(101) syscalls plus a
  ``process_vm_writev`` injection (``privilege_escalation_attempt`` == 1 and
  ``is_injection_target`` == 1).
* ``cryptocurrency_mining`` — sustained connections to a mining-pool IP on 3333
  (and 4444) plus heavy syscall activity and a LOLBin exec.

Pure standard library — no numpy/torch needed. The events are the same decoded
dataclasses the live eBPF collector produces, so a vector that fires here will
fire identically on real captured telemetry.
"""

from __future__ import annotations

from typing import Dict, List

from behaveguard.collector.event_types import (
    AntiforensicEvent,
    ContainerEscapeEvent,
    DnsTunnelEvent,
    FileEvent,
    InjectionEvent,
    LolbinEvent,
    NetworkEvent,
    ProcessEvent,
    RawEvent,
    SyscallEvent,
)


class AttackSimulator:
    """Generates labelled attack event sequences for detection tests."""

    def __init__(self, base_ns: int = 2_000_000_000_000) -> None:
        """Args:
        base_ns: Monotonic nanosecond base timestamp for all generated events.
        """
        self.base_ns = int(base_ns)
        self.pid = 6606
        self.comm = "evil"

    # ------------------------------------------------------------------ #
    # Individual attack vectors
    # ------------------------------------------------------------------ #
    def credential_dumping(self) -> List[RawEvent]:
        """Read the credential stores and SSH private key material.

        The reads target paths under ``/etc`` and ``/root/.ssh`` whose basenames
        are on the sensitive list, so ``files_in_system_dirs`` elevates above 0.
        """
        base = self.base_ns
        targets = ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_rsa"]
        events: List[RawEvent] = []
        for i, path in enumerate(targets):
            events.append(
                FileEvent(
                    timestamp_ns=base + (i * 1_000),
                    pid=self.pid,
                    comm="cat",
                    path=path,
                    operation="open",
                    flags=0,
                    ret=3,
                    bytes_count=0,
                )
            )
            events.append(
                FileEvent(
                    timestamp_ns=base + (i * 1_000) + 500,
                    pid=self.pid,
                    comm="cat",
                    path=path,
                    operation="read",
                    flags=0,
                    ret=4096,
                    bytes_count=4096,
                )
            )
        return events

    def reverse_shell(self) -> List[RawEvent]:
        """Spawn an interactive shell and dial back to a foreign C2 on 4444.

        The ``bash -i`` exec sets ``is_shell_spawned`` == 1; the outbound TCP
        connection to a public (non-RFC1918) IP on port 4444 is the C2 channel.
        """
        base = self.base_ns
        return [
            ProcessEvent(
                timestamp_ns=base + 1_000,
                pid=self.pid,
                ppid=1234,
                comm="bash",
                exe_path="/bin/bash",
                cmdline="bash -i",
                action="exec",
                exit_code=0,
            ),
            NetworkEvent(
                timestamp_ns=base + 2_000,
                pid=self.pid,
                comm="bash",
                src_ip="203.0.113.5",
                dst_ip="198.51.100.66",
                src_port=44321,
                dst_port=4444,
                protocol="TCP",
                bytes_count=256,
                direction="outbound",
            ),
        ]

    def lateral_movement(self) -> List[RawEvent]:
        """Sweep internal RFC1918 hosts and pivot over ssh.

        Outbound connections to ``10.0.0.x`` private addresses set
        ``is_connecting_to_rfc1918`` == 1; the ``ssh`` exec is the pivot.
        """
        base = self.base_ns
        events: List[RawEvent] = []
        for i, host in enumerate(["10.0.0.5", "10.0.0.6", "10.0.0.7"]):
            events.append(
                NetworkEvent(
                    timestamp_ns=base + (i * 1_000),
                    pid=self.pid,
                    comm="ssh",
                    src_ip="10.0.0.2",
                    dst_ip=host,
                    src_port=40000 + i,
                    dst_port=22,
                    protocol="TCP",
                    bytes_count=512,
                    direction="outbound",
                )
            )
        events.append(
            ProcessEvent(
                timestamp_ns=base + 5_000,
                pid=self.pid,
                ppid=1234,
                comm="ssh",
                exe_path="/usr/bin/ssh",
                cmdline="ssh admin@10.0.0.7",
                action="exec",
                exit_code=0,
            )
        )
        return events

    def data_exfiltration(self) -> List[RawEvent]:
        """Stage many files and push a large payload outbound.

        A burst of file reads plus a single large outbound transfer drives
        ``bytes_sent_per_second`` above 0 (and ``unique_files_opened`` up).
        """
        base = self.base_ns
        events: List[RawEvent] = []
        for i in range(12):
            path = f"/srv/data/records/customer_{i:04d}.csv"
            events.append(
                FileEvent(
                    timestamp_ns=base + (i * 500),
                    pid=self.pid,
                    comm="tar",
                    path=path,
                    operation="open",
                    flags=0,
                    ret=5,
                    bytes_count=0,
                )
            )
            events.append(
                FileEvent(
                    timestamp_ns=base + (i * 500) + 250,
                    pid=self.pid,
                    comm="tar",
                    path=path,
                    operation="read",
                    flags=0,
                    ret=65536,
                    bytes_count=65536,
                )
            )
        # Large outbound transfer (~25 MB) to an external collector.
        events.append(
            NetworkEvent(
                timestamp_ns=base + 20_000,
                pid=self.pid,
                comm="curl",
                src_ip="203.0.113.5",
                dst_ip="198.51.100.200",
                src_port=55000,
                dst_port=443,
                protocol="TCP",
                bytes_count=25_000_000,
                direction="outbound",
            )
        )
        return events

    def privilege_escalation(self) -> List[RawEvent]:
        """Drop privileges/trace a victim and write into its memory.

        ``setuid(105)`` and ``ptrace(101)`` syscalls set
        ``privilege_escalation_attempt`` == 1; the ``process_vm_writev``
        :class:`InjectionEvent` sets ``is_injection_target`` == 1.
        """
        base = self.base_ns
        return [
            SyscallEvent(
                timestamp_ns=base + 1_000,
                pid=self.pid,
                tgid=self.pid,
                uid=1000,
                comm=self.comm,
                syscall_nr=105,
                syscall_name="setuid",
                ret=0,
                args=[0, 0, 0],
            ),
            SyscallEvent(
                timestamp_ns=base + 2_000,
                pid=self.pid,
                tgid=self.pid,
                uid=0,
                comm=self.comm,
                syscall_nr=101,
                syscall_name="ptrace",
                ret=0,
                args=[4, 1234, 0],  # PTRACE_ATTACH against victim pid 1234
            ),
            InjectionEvent(
                timestamp_ns=base + 3_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                target_pid=1234,
                method="process_vm_writev",
            ),
        ]

    def cryptocurrency_mining(self) -> List[RawEvent]:
        """Connect to a mining pool and burn CPU.

        Repeated outbound connections to a pool IP on stratum port 3333 (and a
        4444 fallback) drive the network-rate features up; the dense syscall
        stream simulates the hashing loop; a ``xmrig`` :class:`LolbinEvent` flags
        the Living-Off-The-Land execution.
        """
        base = self.base_ns
        events: List[RawEvent] = []
        for i in range(8):
            port = 3333 if i % 2 == 0 else 4444
            events.append(
                NetworkEvent(
                    timestamp_ns=base + (i * 1_000),
                    pid=self.pid,
                    comm="xmrig",
                    src_ip="203.0.113.9",
                    dst_ip="198.51.100.123",
                    src_port=33000 + i,
                    dst_port=port,
                    protocol="TCP",
                    bytes_count=4096,
                    direction="outbound",
                )
            )
        # Dense hashing loop: many getrandom/compute syscalls in the window.
        for i in range(40):
            events.append(
                SyscallEvent(
                    timestamp_ns=base + 10_000 + (i * 100),
                    pid=self.pid,
                    tgid=self.pid,
                    uid=1000,
                    comm="xmrig",
                    syscall_nr=318,  # getrandom
                    syscall_name="getrandom",
                    ret=32,
                    args=[0, 32, 0],
                )
            )
        # LOLBin execution (curl, on the watchlist) used to fetch the miner.
        events.append(
            LolbinEvent(
                timestamp_ns=base + 20_000,
                pid=self.pid,
                ppid=1234,
                uid=1000,
                comm="curl",
            )
        )
        return events

    # ================================================================== #
    # Advanced defense layers — dedicated, isolated simulations.
    #
    # Each function below exercises exactly ONE of the five advanced eBPF
    # layers in isolation (no overlapping signals from other layers), so the
    # assertions in test_detection.py attribute the detection unambiguously to
    # that layer's kernel hook and feature(s).
    # ================================================================== #
    def process_injection(self) -> List[RawEvent]:
        """Process injection — hijacking another process's address space.

        Kernel hooks (injection_monitor.c): ``security_ptrace_access_check``
        (LSM, PTRACE_ATTACH), ``sys_enter_process_vm_writev``, and ``mem_write``
        (writes to ``/proc/<pid>/mem``). All three :class:`InjectionEvent`
        methods are emitted against victim pid 1234, driving
        ``is_injection_target`` -> 1.
        """
        base = self.base_ns
        return [
            InjectionEvent(
                timestamp_ns=base + 1_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                target_pid=1234,
                method="ptrace",
            ),
            InjectionEvent(
                timestamp_ns=base + 2_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                target_pid=1234,
                method="proc_mem",
            ),
            InjectionEvent(
                timestamp_ns=base + 3_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                target_pid=1234,
                method="process_vm_writev",
            ),
        ]

    def container_escape(self) -> List[RawEvent]:
        """Container escape — breaking out of namespace isolation.

        Kernel hooks (container_escape_monitor.c): ``sys_enter_setns``,
        ``sys_enter_unshare``, ``sys_enter_pivot_root``. The setns/unshare pair
        drives ``namespace_change_count`` > 0 and the pivot_root sets
        ``pivot_root_attempt`` -> 1.
        """
        base = self.base_ns
        return [
            ContainerEscapeEvent(
                timestamp_ns=base + 1_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="setns",
                flags=0x08000000,
            ),
            ContainerEscapeEvent(
                timestamp_ns=base + 2_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="unshare",
                flags=0x10000000,
            ),
            ContainerEscapeEvent(
                timestamp_ns=base + 3_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="pivot_root",
                flags=0,
            ),
        ]

    def lolbin_execution(self) -> List[RawEvent]:
        """LOLBin abuse — Living-Off-The-Land binary execution.

        Kernel hook (lolbin_monitor.c): ``sched_process_exec`` matched against
        the watchlist. Executes ``wget``, ``nc``, ``base64``, and ``chmod`` so
        ``lolbin_execution_count`` rises and the per-binary one-hot flags
        (``lolbin_nc``, ``lolbin_chmod`` …) -> 1.
        """
        base = self.base_ns
        return [
            LolbinEvent(
                timestamp_ns=base + (i * 1_000), pid=self.pid, ppid=1234, uid=1000, comm=binary
            )
            for i, binary in enumerate(["wget", "nc", "base64", "chmod"])
        ]

    def antiforensic_log_clearing(self) -> List[RawEvent]:
        """Anti-forensics — destroying and timestomping logs under /var/log.

        Kernel hooks (antiforensic_monitor.c): ``security_inode_unlink``,
        ``sys_enter_truncate``, ``sys_enter_utimensat`` (filtered to
        ``/var/log``). The unlink/truncate drive ``log_deletion_count`` > 0 and
        the utimensat timestomp drives ``timestamp_modification_count`` > 0.
        """
        base = self.base_ns
        return [
            AntiforensicEvent(
                timestamp_ns=base + 1_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="unlink",
                path="/var/log/auth.log",
            ),
            AntiforensicEvent(
                timestamp_ns=base + 2_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="truncate",
                path="/var/log/syslog",
            ),
            AntiforensicEvent(
                timestamp_ns=base + 3_000,
                pid=self.pid,
                uid=0,
                comm=self.comm,
                action="timestomp",
                path="/var/log/wtmp",
            ),
        ]

    def dns_tunneling(self) -> List[RawEvent]:
        """DNS tunneling — exfiltration inside oversized DNS queries.

        Kernel hook (dns_tunnel_monitor.c): ``udp_sendmsg`` to port 53 with a
        payload > 100 bytes. A burst of large (220-480 byte) :class:`DnsTunnelEvent`
        queries drives ``max_dns_payload_bytes``, ``avg_dns_query_size``, and
        ``dns_query_rate`` above 0.
        """
        base = self.base_ns
        payloads = [220, 300, 380, 420, 480]
        return [
            DnsTunnelEvent(
                timestamp_ns=base + (i * 1_000),
                pid=self.pid,
                uid=1000,
                comm="exfil",
                dst_ip="198.51.100.53",
                dst_port=53,
                payload_size=size,
            )
            for i, size in enumerate(payloads)
        ]

    # ------------------------------------------------------------------ #
    # Aggregate
    # ------------------------------------------------------------------ #
    def advanced_attacks(self) -> Dict[str, List[RawEvent]]:
        """Return the five advanced-defense-layer vectors keyed by name."""
        return {
            "process_injection": self.process_injection(),
            "container_escape": self.container_escape(),
            "lolbin_execution": self.lolbin_execution(),
            "antiforensic_log_clearing": self.antiforensic_log_clearing(),
            "dns_tunneling": self.dns_tunneling(),
        }

    def all_attacks(self) -> Dict[str, List[RawEvent]]:
        """Return every attack vector (classic + advanced) keyed by name."""
        attacks = {
            "credential_dumping": self.credential_dumping(),
            "reverse_shell": self.reverse_shell(),
            "lateral_movement": self.lateral_movement(),
            "data_exfiltration": self.data_exfiltration(),
            "privilege_escalation": self.privilege_escalation(),
            "cryptocurrency_mining": self.cryptocurrency_mining(),
        }
        attacks.update(self.advanced_attacks())
        return attacks
