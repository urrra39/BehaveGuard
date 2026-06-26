"""Process-lifecycle + advanced-defense features.

The process tree is the backbone of behavioral detection: a web server that
suddenly spawns ``sh`` and then ``nc`` is the classic exploitation chain. On top
of the base process features (spawn volume, shell spawning, privilege-escalation
syscalls), this extractor folds in three of the advanced eBPF defense layers
whose events are process-centric:

* **process injection** — one process writing another's memory,
* **container escape** — namespace manipulation (setns/unshare/pivot_root),
* **LOLBins** — execution of Living-Off-The-Land binaries from a watchlist.

All values are squashed into ``[0, 1]``; the boolean signals (shell spawn,
injection target, pivot_root) stay 0/1 and are given very high salience by the
explainer.
"""

from __future__ import annotations

from typing import List, Optional

from behaveguard.collector.event_types import (
    ContainerEscapeEvent,
    InjectionEvent,
    LolbinEvent,
    ProcessEvent,
    SyscallEvent,
)

CAP_SPAWNS = 20.0
CAP_NAMESPACE = 5.0  # namespace changes -> a couple already looks like escape prep
CAP_LOLBIN = 10.0  # LOLBin executions per window

# Interactive shells whose appearance under an unexpected parent is suspicious.
SHELLS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "csh",
    "tcsh",
    "ash",
    "busybox",
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

# LOLBin watchlist (one-hot feature per entry). The matcher accepts a small set
# of aliases per name (e.g. python3 counts as python) since ``comm`` carries the
# concrete binary name.
LOLBIN_WATCHLIST = [
    "wget",
    "curl",
    "python",
    "perl",
    "bash",
    "nc",
    "ncat",
    "socat",
    "base64",
    "xxd",
    "dd",
    "crontab",
    "at",
    "systemctl",
    "chmod",
]
_LOLBIN_ALIASES = {
    "python": {"python", "python3", "python2"},
    "perl": {"perl"},
}


def _saturate(value: float, cap: float) -> float:
    if cap <= 0.0:
        return 0.0
    return min(value / cap, 1.0)


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""


def _lolbin_match(comm: str, name: str) -> bool:
    """True if process ``comm`` corresponds to watchlist ``name`` (with aliases)."""
    return comm in _LOLBIN_ALIASES.get(name, {name})


class ProcessFeatureExtractor:
    """Aggregates process, syscall, injection, container, and LOLBin events."""

    @staticmethod
    def feature_names() -> List[str]:
        names = [
            "child_processes_spawned",
            "is_shell_spawned",
            "privilege_escalation_attempt",
            # Process-injection defense layer.
            "is_injection_target",
            # Container-escape defense layer.
            "namespace_change_count",
            "pivot_root_attempt",
            # LOLBin defense layer.
            "lolbin_execution_count",
        ]
        names.extend(f"lolbin_{binary}" for binary in LOLBIN_WATCHLIST)
        return names

    @staticmethod
    def dim() -> int:
        return 3 + 4 + len(LOLBIN_WATCHLIST)

    def extract(
        self,
        process_events: List[ProcessEvent],
        syscall_events: List[SyscallEvent],
        window_seconds: int,
        injection_events: Optional[List[InjectionEvent]] = None,
        container_events: Optional[List[ContainerEscapeEvent]] = None,
        lolbin_events: Optional[List[LolbinEvent]] = None,
    ) -> List[float]:
        # --- base process features ---
        spawned = 0
        shell_spawned = 0.0
        for event in process_events:
            if event.action in ("exec", "fork"):
                spawned += 1
            names = {
                (event.comm or "").lower(),
                _basename(event.exe_path).lower(),
            }
            if event.cmdline:
                names.add(_basename(event.cmdline.split()[0]).lower())
            if names & SHELLS:
                shell_spawned = 1.0

        priv_esc = 0.0
        for syscall_event in syscall_events:
            if int(syscall_event.syscall_nr) in PRIV_ESC_SYSCALLS:
                priv_esc = 1.0
                break

        # --- process injection ---
        injection = injection_events or []
        is_injection_target = 1.0 if injection else 0.0

        # --- container escape ---
        containers = container_events or []
        namespace_changes = sum(1 for e in containers if e.action in ("setns", "unshare"))
        pivot_root = 1.0 if any(e.action == "pivot_root" for e in containers) else 0.0

        # --- LOLBins ---
        lolbins = lolbin_events or []
        lolbin_comms = [(e.comm or "").lower() for e in lolbins]
        one_hot = [
            1.0 if any(_lolbin_match(c, binary) for c in lolbin_comms) else 0.0
            for binary in LOLBIN_WATCHLIST
        ]

        return [
            _saturate(spawned, CAP_SPAWNS),
            shell_spawned,
            priv_esc,
            is_injection_target,
            _saturate(namespace_changes, CAP_NAMESPACE),
            pivot_root,
            _saturate(len(lolbins), CAP_LOLBIN),
            *one_hot,
        ]
