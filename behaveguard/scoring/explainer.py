"""Human-readable explanations for why a process was flagged.

A lightweight, SHAP-style attribution: each feature's contribution is its
deviation from the learned baseline (or its raw value when no baseline is
available), weighted by a *salience* factor so that directly-interpretable
behavioral features (shell spawns, sensitive-file access, Tor connections, and
sensitive syscalls) surface ahead of high-frequency-but-benign syscalls like
``read``/``write``. The top contributors are rendered into a plain-English
sentence and returned alongside structured detail.

This module is pure Python (no torch/numpy) and imports anywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence

from behaveguard.collector.event_types import SENSITIVE_SYSCALLS, syscall_name

# Threshold below which a contribution is considered noise and ignored.
_MIN_CONTRIBUTION = 0.05

# Static phrases for the named (semantic) features.
_PHRASES = {
    "unique_remote_ips": "contacted an unusual number of remote IPs",
    "unique_remote_ports": "probed an unusual number of remote ports",
    "outbound_connection_rate": "opened outbound connections at a high rate",
    "bytes_sent_per_second": "sent data at an unusually high rate",
    "bytes_recv_per_second": "received data at an unusually high rate",
    "is_using_tor_port": "connected to a Tor port",
    "is_connecting_to_rfc1918": "connected to a private/internal address",
    "unique_files_opened": "opened an unusual number of distinct files",
    "files_in_system_dirs": "accessed sensitive system files",
    "executable_files_opened": "opened executable files",
    "files_written_count": "wrote to an unusual number of files",
    "entropy_of_file_paths": "accessed files with high-entropy paths",
    "child_processes_spawned": "spawned an unusual number of child processes",
    "is_shell_spawned": "spawned a shell process",
    "privilege_escalation_attempt": "attempted privilege escalation (setuid/ptrace)",
    "window_duration_ms": "showed an unusual activity span",
    "events_per_second": "generated events at an unusually high rate",
    "cpu_time_ratio": "ran with an unusually high activity duty cycle",
    # --- advanced defense layers (explicit, decisive callouts) ---
    "is_injection_target": "is a Process Injection Target (a foreign process is writing its memory)",
    "namespace_change_count": "changed namespaces — possible Container Escape preparation",
    "pivot_root_attempt": "made a Container Escape Attempt (pivot_root)",
    "lolbin_execution_count": "executed Living-Off-The-Land binaries (LOLBins)",
    "log_deletion_count": "deleted or truncated log files (anti-forensic evidence destruction)",
    "timestamp_modification_count": "tampered with file timestamps (timestomping)",
    "avg_dns_query_size": "issued oversized DNS queries",
    "dns_query_rate": "issued DNS queries at an unusually high rate",
    "max_dns_payload_bytes": "shows DNS Tunneling Exfiltration (oversized DNS payloads)",
}

# Advanced defense-layer features are decisive: a single hit should dominate the
# explanation, so they get a much higher salience than ordinary behavioral drift.
_CRITICAL_DEFENSE_FEATURES = {
    "is_injection_target",
    "pivot_root_attempt",
    "namespace_change_count",
    "lolbin_execution_count",
    "log_deletion_count",
    "timestamp_modification_count",
    "avg_dns_query_size",
    "dns_query_rate",
    "max_dns_payload_bytes",
}


@dataclass
class FeatureContribution:
    """One feature's contribution to an anomaly verdict."""

    name: str
    value: float
    contribution: float
    phrase: str


def _syscall_index(name: str, prefix: str) -> Optional[int]:
    """Return the integer index from ``<prefix><i><suffix>`` names, else None."""
    if not name.startswith(prefix):
        return None
    rest = name[len(prefix):]
    digits = rest.split("_", 1)[0]
    return int(digits) if digits.isdigit() else None


def _salience_weight(name: str) -> float:
    """Relative importance of a feature for *explanation* purposes."""
    if name in _CRITICAL_DEFENSE_FEATURES:
        return 3.0
    if name.startswith("lolbin_"):  # one-hot LOLBin flags (e.g. lolbin_nc)
        return 2.5
    if name in _PHRASES:
        return 1.0
    sys_idx = _syscall_index(name, "syscall_")
    if sys_idx is not None and name.endswith("_freq"):
        return 1.0 if sys_idx in SENSITIVE_SYSCALLS else 0.2
    if name.startswith("syscall_bigram_"):
        return 0.3
    return 0.5


def _phrase_for(name: str) -> str:
    """Human phrase describing an elevated value of ``name``."""
    if name in _PHRASES:
        return _PHRASES[name]
    if name.startswith("lolbin_"):  # one-hot LOLBin flag for a specific binary
        binary = name[len("lolbin_"):]
        return f"executed the LOLBin '{binary}'"
    sys_idx = _syscall_index(name, "syscall_")
    if sys_idx is not None and name.endswith("_freq"):
        return f"elevated use of the {syscall_name(sys_idx)} syscall"
    if name.startswith("syscall_bigram_"):
        return "an unusual syscall sequence pattern"
    return f"an elevated {name}"


def rank_contributions(
    feature_vector: Sequence[float],
    feature_names: Sequence[str],
    baseline: Optional[Sequence[float]] = None,
) -> List[FeatureContribution]:
    """Rank features by salience-weighted deviation from baseline (descending).

    Args:
        feature_vector: The observed feature values.
        feature_names: Names aligned with ``feature_vector``.
        baseline: Optional per-feature baseline (e.g. training means); when
            omitted, the raw value is used as the deviation.

    Returns:
        Contributions sorted from most to least salient.
    """
    contributions: List[FeatureContribution] = []
    for i, (name, value) in enumerate(zip(feature_names, feature_vector)):
        base = float(baseline[i]) if baseline is not None and i < len(baseline) else 0.0
        deviation = abs(float(value) - base)
        salience = deviation * _salience_weight(name)
        contributions.append(
            FeatureContribution(
                name=name,
                value=float(value),
                contribution=salience,
                phrase=_phrase_for(name),
            )
        )
    contributions.sort(key=lambda c: c.contribution, reverse=True)
    return contributions


def explain(
    feature_vector: Sequence[float],
    feature_names: Sequence[str],
    process_name: str,
    baseline: Optional[Sequence[float]] = None,
    top_k: int = 3,
) -> str:
    """Build a one-sentence explanation of why a process looks anomalous.

    Args:
        feature_vector: Observed feature values.
        feature_names: Names aligned with ``feature_vector``.
        process_name: Name of the process being explained.
        baseline: Optional per-feature baseline for deviation scoring.
        top_k: Maximum number of contributing features to mention.

    Returns:
        A readable sentence; a mild-deviation fallback if nothing is notable.
    """
    ranked = rank_contributions(feature_vector, feature_names, baseline)
    notable = [c for c in ranked if c.contribution >= _MIN_CONTRIBUTION][:top_k]

    if not notable:
        return f"Process {process_name} shows only mild deviations from its baseline."

    clauses = [f"{c.phrase} ({c.name}={c.value:.2f})" for c in notable]
    if len(clauses) == 1:
        body = clauses[0]
    elif len(clauses) == 2:
        body = f"{clauses[0]} and {clauses[1]}"
    else:
        body = ", ".join(clauses[:-1]) + f", and {clauses[-1]}"
    return f"Process {process_name} {body}."
