"""Process-lifecycle features derived from process events (+ syscall context).

The process tree is the backbone of behavioral detection: a web server that
suddenly spawns ``sh`` and then ``nc`` is the classic exploitation chain. Shell
spawning and privilege-escalation syscalls are kept as high-signal booleans;
spawn volume is rate-capped into ``[0, 1]``.
"""

from __future__ import annotations

from typing import List

from behaveguard.collector.event_types import ProcessEvent, SyscallEvent

CAP_SPAWNS = 20.0

# Interactive shells whose appearance under an unexpected parent is suspicious.
SHELLS = {
    "sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash", "busybox",
}

# Syscalls that change credentials, trace other processes, or alter process
# privileges — privilege-escalation / tampering primitives.
PRIV_ESC_SYSCALLS = {
    105,  # setuid
    106,  # setgid
    117,  # setresuid
    119,  # setresgid
    157,  # prctl
    101,  # ptrace
}


def _saturate(value: float, cap: float) -> float:
    if cap <= 0.0:
        return 0.0
    return min(value / cap, 1.0)


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""


class ProcessFeatureExtractor:
    """Aggregates process (and supporting syscall) events into three features."""

    @staticmethod
    def feature_names() -> List[str]:
        return [
            "child_processes_spawned",
            "is_shell_spawned",
            "privilege_escalation_attempt",
        ]

    @staticmethod
    def dim() -> int:
        return 3

    def extract(
        self,
        process_events: List[ProcessEvent],
        syscall_events: List[SyscallEvent],
        window_seconds: int,
    ) -> List[float]:
        spawned = 0
        shell_spawned = 0.0

        for event in process_events:
            if event.action in ("exec", "fork"):
                spawned += 1

            names = {
                (event.comm or "").lower(),
                _basename(event.exe_path).lower(),
            }
            # First token of the command line, if present.
            if event.cmdline:
                names.add(_basename(event.cmdline.split()[0]).lower())
            if names & SHELLS:
                shell_spawned = 1.0

        priv_esc = 0.0
        for event in syscall_events:
            if int(event.syscall_nr) in PRIV_ESC_SYSCALLS:
                priv_esc = 1.0
                break

        return [
            _saturate(spawned, CAP_SPAWNS),
            shell_spawned,
            priv_esc,
        ]
