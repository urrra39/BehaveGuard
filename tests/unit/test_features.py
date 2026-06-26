"""Unit tests for the pure-Python feature extraction path.

These exercise ``FeatureExtractor.extract_vector`` directly (a ``list[float]``),
which needs no numpy/torch, so they run in the local environment as well as CI.
"""

from __future__ import annotations

import pytest

from behaveguard.collector.event_types import (
    AntiforensicEvent,
    ContainerEscapeEvent,
    DnsTunnelEvent,
    FileEvent,
    InjectionEvent,
    LolbinEvent,
    NetworkEvent,
    ProcessEvent,
    SyscallEvent,
)
from behaveguard.features.extractor import FeatureExtractor


@pytest.fixture()
def extractor():
    return FeatureExtractor(window_seconds=30)


def _attack_window(base_ns: int = 5_000_000_000_000):
    """A small window that should trip the shell-spawn and sensitive-file flags."""
    return [
        ProcessEvent(
            timestamp_ns=base_ns + 1_000,
            pid=900,
            ppid=1,
            comm="bash",
            exe_path="/bin/bash",
            cmdline="bash -i",
            action="exec",
            exit_code=0,
        ),
        FileEvent(
            timestamp_ns=base_ns + 2_000,
            pid=900,
            comm="cat",
            path="/etc/shadow",
            operation="read",
            flags=0,
            ret=4096,
            bytes_count=4096,
        ),
        SyscallEvent(
            timestamp_ns=base_ns + 3_000,
            pid=900,
            tgid=900,
            uid=0,
            comm="bash",
            syscall_nr=59,
            syscall_name="execve",
            ret=0,
            args=[0, 0, 0],
        ),
    ]


def test_feature_names_length_matches_num_features():
    """FEATURE_NAMES and NUM_FEATURES are consistent and equal to 427."""
    assert FeatureExtractor.NUM_FEATURES == 427
    assert len(FeatureExtractor.FEATURE_NAMES) == 427
    # Names are unique (no accidental duplicate slots).
    assert len(set(FeatureExtractor.FEATURE_NAMES)) == 427


def test_extract_vector_length_is_427(extractor):
    vector = extractor.extract_vector(_attack_window())
    assert isinstance(vector, list)
    assert len(vector) == 427


def test_extract_vector_all_values_in_unit_interval(extractor):
    vector = extractor.extract_vector(_attack_window())
    for i, value in enumerate(vector):
        assert isinstance(value, float)
        assert (
            0.0 <= value <= 1.0
        ), f"feature {FeatureExtractor.FEATURE_NAMES[i]} out of [0,1]: {value}"


def test_extract_vector_is_deterministic_on_repeat(extractor):
    """Identical input -> identical output (no PYTHONHASHSEED drift in bigrams)."""
    events = _attack_window()
    first = extractor.extract_vector(events)
    second = extractor.extract_vector(events)
    assert first == second


def test_empty_window_is_all_zeros(extractor):
    vector = extractor.extract_vector([])
    assert len(vector) == 427
    assert all(value == 0.0 for value in vector)


def test_attack_window_lights_up_signature_features(extractor):
    """A shell exec + /etc/shadow read trips is_shell_spawned and files_in_system_dirs."""
    vector = extractor.extract_vector(_attack_window())
    names = FeatureExtractor.FEATURE_NAMES

    is_shell_spawned = vector[names.index("is_shell_spawned")]
    files_in_system_dirs = vector[names.index("files_in_system_dirs")]

    assert is_shell_spawned == 1.0
    assert files_in_system_dirs > 0.0


def _advanced_layers_window(base_ns: int = 7_000_000_000_000):
    """One event from each of the five advanced eBPF defense layers."""
    return [
        # 1. Process injection (process_vm_writev into a victim).
        InjectionEvent(
            timestamp_ns=base_ns + 1,
            pid=900,
            uid=0,
            comm="evil",
            target_pid=42,
            method="process_vm_writev",
        ),
        # 2. Container escape (namespace change + pivot_root).
        ContainerEscapeEvent(
            timestamp_ns=base_ns + 2, pid=900, uid=0, comm="evil", action="setns", flags=0
        ),
        ContainerEscapeEvent(
            timestamp_ns=base_ns + 3, pid=900, uid=0, comm="evil", action="pivot_root", flags=0
        ),
        # 3. LOLBin execution (nc on the watchlist).
        LolbinEvent(timestamp_ns=base_ns + 4, pid=900, ppid=1, uid=0, comm="nc"),
        # 4. Anti-forensic (log unlink + timestomp under /var/log).
        AntiforensicEvent(
            timestamp_ns=base_ns + 5,
            pid=900,
            uid=0,
            comm="evil",
            action="unlink",
            path="/var/log/auth.log",
        ),
        AntiforensicEvent(
            timestamp_ns=base_ns + 6,
            pid=900,
            uid=0,
            comm="evil",
            action="timestomp",
            path="/var/log/wtmp",
        ),
        # 5. DNS tunneling (oversized UDP/53 query).
        DnsTunnelEvent(
            timestamp_ns=base_ns + 7,
            pid=900,
            uid=0,
            comm="evil",
            dst_ip="198.51.100.53",
            dst_port=53,
            payload_size=400,
        ),
    ]


def test_advanced_defense_layers_all_fire(extractor):
    """All five advanced eBPF defense layers light up their dedicated features.

    This is the comprehensive coverage guarantee for the advanced pillars:
    process injection, container escape, LOLBin execution, anti-forensics, and
    DNS tunneling each contribute a non-trivial, correctly-located feature.
    """
    vector = extractor.extract_vector(_advanced_layers_window())
    names = FeatureExtractor.FEATURE_NAMES

    def f(name: str) -> float:
        return vector[names.index(name)]

    # 1. Process injection.
    assert f("is_injection_target") == 1.0
    # 2. Container escape.
    assert f("namespace_change_count") > 0.0
    assert f("pivot_root_attempt") == 1.0
    # 3. LOLBin execution.
    assert f("lolbin_execution_count") > 0.0
    assert f("lolbin_nc") == 1.0
    # 4. Anti-forensic log clearing.
    assert f("log_deletion_count") > 0.0
    assert f("timestamp_modification_count") > 0.0
    # 5. DNS tunneling payload size.
    assert f("max_dns_payload_bytes") > 0.0
    assert f("avg_dns_query_size") > 0.0
    assert f("dns_query_rate") > 0.0

    # All values remain in the unit interval.
    assert all(0.0 <= v <= 1.0 for v in vector)


def test_window_seconds_override_changes_rate_features(extractor):
    """A shorter window raises rate-based features for the same event count."""
    # Many outbound connections so the rate feature is below saturation and the
    # window length actually moves it.
    base = 6_000_000_000_000
    events = [
        NetworkEvent(
            timestamp_ns=base + i * 1_000,
            pid=10,
            comm="curl",
            src_ip="203.0.113.1",
            dst_ip="198.51.100.2",
            src_port=40000 + i,
            dst_port=443,
            protocol="TCP",
            bytes_count=100,
            direction="outbound",
        )
        for i in range(10)
    ]
    names = FeatureExtractor.FEATURE_NAMES
    idx = names.index("outbound_connection_rate")

    long_window = extractor.extract_vector(events, window_seconds=300)
    short_window = extractor.extract_vector(events, window_seconds=1)

    assert short_window[idx] > long_window[idx]
    assert 0.0 <= long_window[idx] <= 1.0
    assert 0.0 <= short_window[idx] <= 1.0
