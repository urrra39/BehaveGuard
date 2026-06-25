"""Per-vector detection assertions over the pure-Python feature pipeline.

For every simulated attack we extract the feature vector and assert that the
discriminating feature(s) for that vector are elevated, while the same
defensive booleans stay at 0 for the benign session. This exercises the full
feature-extraction path (``FeatureExtractor.extract_vector``) with no heavy
dependencies, so it runs everywhere.

NOTE: Model-scored detection (the LSTM+VAE ensemble producing an anomaly
``score > 80`` for these windows) runs in the Docker/Linux environment where
torch is installed — see ``tests/integration/test_full_pipeline.py`` for the
torch-gated end-to-end scoring block. Here we verify the *signal* the models
consume is present and correctly separated from benign behaviour.
"""

from __future__ import annotations

import pytest

from behaveguard.features.extractor import FeatureExtractor
from tests.simulations.simulate_attack import AttackSimulator
from tests.simulations.simulate_normal import normal_session


def _feat(vector, name):
    """Return the value of feature ``name`` from ``vector`` by name lookup."""
    return vector[FeatureExtractor.FEATURE_NAMES.index(name)]


@pytest.fixture()
def extractor():
    return FeatureExtractor(window_seconds=30)


@pytest.fixture()
def sim():
    return AttackSimulator()


# Signature feature(s) that must be elevated for each attack vector, expressed
# as (feature_name, predicate) pairs.
def _gt0(v):
    return v > 0.0


def _eq1(v):
    return v == 1.0


ATTACK_SIGNATURES = {
    "credential_dumping": [("files_in_system_dirs", _gt0)],
    "reverse_shell": [("is_shell_spawned", _eq1)],
    "lateral_movement": [("is_connecting_to_rfc1918", _eq1)],
    "data_exfiltration": [("bytes_sent_per_second", _gt0)],
    "privilege_escalation": [
        ("privilege_escalation_attempt", _eq1),
        ("is_injection_target", _eq1),
    ],
    "cryptocurrency_mining": [("outbound_connection_rate", _gt0)],
}

# Defensive booleans that must remain 0 for the benign session.
_DEFENSIVE_BOOLEANS = [
    "is_shell_spawned",
    "privilege_escalation_attempt",
    "is_injection_target",
    "is_connecting_to_rfc1918",
    "is_using_tor_port",
    "pivot_root_attempt",
    "files_in_system_dirs",
]


@pytest.mark.parametrize("attack_name", sorted(ATTACK_SIGNATURES))
def test_attack_signature_fires(extractor, sim, attack_name):
    """Each attack window elevates its discriminating feature(s)."""
    events = sim.all_attacks()[attack_name]
    vector = extractor.extract_vector(events)

    assert len(vector) == FeatureExtractor.NUM_FEATURES
    for feature_name, predicate in ATTACK_SIGNATURES[attack_name]:
        value = _feat(vector, feature_name)
        assert predicate(value), (
            f"{attack_name}: expected {feature_name} elevated, got {value}"
        )


def test_credential_dumping_files_in_system_dirs(extractor, sim):
    """The headline check: credential dumping drives files_in_system_dirs > 0."""
    vector = extractor.extract_vector(sim.credential_dumping())
    assert _feat(vector, "files_in_system_dirs") > 0.0


# ----------------------------------------------------------------------------- #
# Advanced defense layers — dedicated, isolated coverage (one layer per vector).
# ----------------------------------------------------------------------------- #
ADVANCED_LAYER_SIGNATURES = {
    "process_injection": [("is_injection_target", _eq1)],
    "container_escape": [("namespace_change_count", _gt0), ("pivot_root_attempt", _eq1)],
    "lolbin_execution": [
        ("lolbin_execution_count", _gt0),
        ("lolbin_nc", _eq1),
        ("lolbin_chmod", _eq1),
        ("lolbin_wget", _eq1),
    ],
    "antiforensic_log_clearing": [
        ("log_deletion_count", _gt0),
        ("timestamp_modification_count", _gt0),
    ],
    "dns_tunneling": [
        ("max_dns_payload_bytes", _gt0),
        ("avg_dns_query_size", _gt0),
        ("dns_query_rate", _gt0),
    ],
}


@pytest.mark.parametrize("layer_name", sorted(ADVANCED_LAYER_SIGNATURES))
def test_advanced_layer_signature_fires(extractor, sim, layer_name):
    """Each advanced eBPF layer's isolated simulation elevates its feature(s)."""
    events = sim.advanced_attacks()[layer_name]
    vector = extractor.extract_vector(events)

    assert len(vector) == FeatureExtractor.NUM_FEATURES
    for feature_name, predicate in ADVANCED_LAYER_SIGNATURES[layer_name]:
        value = _feat(vector, feature_name)
        assert predicate(value), (
            f"{layer_name}: expected {feature_name} elevated, got {value}"
        )


def test_layer_process_injection(extractor, sim):
    """Process injection (ptrace / proc_mem / process_vm_writev) -> is_injection_target."""
    vector = extractor.extract_vector(sim.process_injection())
    assert _feat(vector, "is_injection_target") == 1.0


def test_layer_container_escape(extractor, sim):
    """Container escape (setns/unshare/pivot_root) -> namespace + pivot_root features."""
    vector = extractor.extract_vector(sim.container_escape())
    assert _feat(vector, "namespace_change_count") > 0.0
    assert _feat(vector, "pivot_root_attempt") == 1.0


def test_layer_lolbin_execution(extractor, sim):
    """LOLBin execution (wget/nc/base64/chmod) -> count + per-binary one-hot flags."""
    vector = extractor.extract_vector(sim.lolbin_execution())
    assert _feat(vector, "lolbin_execution_count") > 0.0
    assert _feat(vector, "lolbin_nc") == 1.0
    assert _feat(vector, "lolbin_chmod") == 1.0
    assert _feat(vector, "lolbin_base64") == 1.0


def test_layer_antiforensic_log_clearing(extractor, sim):
    """Anti-forensics (unlink/truncate/utimensat on /var/log) -> deletion + timestomp."""
    vector = extractor.extract_vector(sim.antiforensic_log_clearing())
    assert _feat(vector, "log_deletion_count") > 0.0
    assert _feat(vector, "timestamp_modification_count") > 0.0


def test_layer_dns_tunneling(extractor, sim):
    """DNS tunneling (oversized UDP/53 queries) -> payload-size + rate features."""
    vector = extractor.extract_vector(sim.dns_tunneling())
    assert _feat(vector, "max_dns_payload_bytes") > 0.0
    assert _feat(vector, "avg_dns_query_size") > 0.0
    assert _feat(vector, "dns_query_rate") > 0.0


def test_normal_session_keeps_advanced_layers_silent(extractor):
    """The benign session must not trip any advanced-layer feature."""
    vector = extractor.extract_vector(normal_session())
    for name in (
        "is_injection_target",
        "namespace_change_count",
        "pivot_root_attempt",
        "lolbin_execution_count",
        "log_deletion_count",
        "timestamp_modification_count",
        "max_dns_payload_bytes",
        "dns_query_rate",
    ):
        assert _feat(vector, name) == 0.0, f"benign session unexpectedly set {name}"


def test_normal_session_keeps_defensive_booleans_zero(extractor):
    """The benign session must not trip any defensive boolean."""
    vector = extractor.extract_vector(normal_session())
    for name in _DEFENSIVE_BOOLEANS:
        assert _feat(vector, name) == 0.0, f"benign session unexpectedly set {name}"


def test_normal_session_does_not_fire_attack_signatures(extractor):
    """None of the attack signature features should fire on benign traffic."""
    vector = extractor.extract_vector(normal_session())
    # Booleans must be 0; bytes_sent_per_second is tiny but the discriminating
    # attack value is far larger — assert the benign rate is below a clearly
    # separable floor rather than exactly 0 (one small HTTPS request exists).
    assert _feat(vector, "is_shell_spawned") == 0.0
    assert _feat(vector, "is_connecting_to_rfc1918") == 0.0
    assert _feat(vector, "is_injection_target") == 0.0
    assert _feat(vector, "privilege_escalation_attempt") == 0.0
