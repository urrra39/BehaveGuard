"""End-to-end pipeline integration: simulations -> features -> (torch) scoring.

The pure-Python portion (simulations -> ``extract_vector`` -> feature assertions)
runs everywhere. A torch-gated block then builds a tiny LSTM + VAE, calibrates a
baseline, and scores a real attack window to prove the whole pipeline runs end to
end. The torch block skips cleanly where torch is absent.
"""

from __future__ import annotations

import pytest

from behaveguard.features.extractor import FeatureExtractor
from tests.simulations.simulate_attack import AttackSimulator
from tests.simulations.simulate_normal import normal_session


def _feat(vector, name):
    return vector[FeatureExtractor.FEATURE_NAMES.index(name)]


@pytest.fixture()
def extractor():
    return FeatureExtractor(window_seconds=30)


@pytest.fixture()
def sim():
    return AttackSimulator()


# --------------------------------------------------------------------------- #
# Pure-Python feature pipeline
# --------------------------------------------------------------------------- #
def test_normal_session_defensive_booleans_are_zero(extractor):
    vector = extractor.extract_vector(normal_session())
    for name in (
        "is_shell_spawned",
        "privilege_escalation_attempt",
        "is_injection_target",
        "is_connecting_to_rfc1918",
        "is_using_tor_port",
        "pivot_root_attempt",
        "files_in_system_dirs",
    ):
        assert _feat(vector, name) == 0.0, f"benign session set {name}"


def test_each_attack_fires_its_signature(extractor, sim):
    attacks = sim.all_attacks()

    cred = extractor.extract_vector(attacks["credential_dumping"])
    assert _feat(cred, "files_in_system_dirs") > 0.0

    shell = extractor.extract_vector(attacks["reverse_shell"])
    assert _feat(shell, "is_shell_spawned") == 1.0

    lateral = extractor.extract_vector(attacks["lateral_movement"])
    assert _feat(lateral, "is_connecting_to_rfc1918") == 1.0

    exfil = extractor.extract_vector(attacks["data_exfiltration"])
    assert _feat(exfil, "bytes_sent_per_second") > 0.0

    privesc = extractor.extract_vector(attacks["privilege_escalation"])
    assert _feat(privesc, "privilege_escalation_attempt") == 1.0
    assert _feat(privesc, "is_injection_target") == 1.0

    crypto = extractor.extract_vector(attacks["cryptocurrency_mining"])
    assert _feat(crypto, "outbound_connection_rate") > 0.0


# --------------------------------------------------------------------------- #
# Torch-gated end-to-end scoring
# --------------------------------------------------------------------------- #
def test_pipeline_scores_a_window_end_to_end(extractor, sim):
    """Build tiny LSTM+VAE, calibrate, and score an attack window in [0,1]."""
    torch = pytest.importorskip("torch")
    from behaveguard.models.autoencoder import BehaviorAutoencoder
    from behaveguard.models.lstm_detector import LSTMDetector

    d = FeatureExtractor.NUM_FEATURES
    seq_len = 4

    # Feature vectors for a benign baseline and an attack window.
    normal_vec = extractor.extract_vector(normal_session())
    attack_vec = extractor.extract_vector(sim.reverse_shell())

    # --- VAE over a single window ---
    vae = BehaviorAutoencoder(input_dim=d, latent_dim=8)
    vae.set_baseline(mean=0.0, std=1.0)
    vae_input = torch.tensor([attack_vec], dtype=torch.float32)  # (1, D)
    vae_score = vae.anomaly_score(vae_input)
    assert isinstance(vae_score, float)
    assert 0.0 <= vae_score <= 1.0

    # --- LSTM over a short sequence of windows ---
    lstm = LSTMDetector(input_dim=d, hidden_dim=16, num_layers=1, sequence_length=seq_len)
    lstm.set_baseline(mean=0.0, std=1.0)
    # Sequence: a few benign windows then the attack window.
    sequence = [normal_vec, normal_vec, normal_vec, attack_vec]
    lstm_input = torch.tensor([sequence], dtype=torch.float32)  # (1, S, D)
    recon, hidden = lstm(lstm_input)
    assert tuple(recon.shape) == (1, seq_len, d)
    assert tuple(hidden.shape) == (1, 16)

    lstm_score = lstm.anomaly_score(lstm_input)
    assert isinstance(lstm_score, float)
    assert 0.0 <= lstm_score <= 1.0

    # --- Weighted ensemble (the production combination of the two scores) ---
    lstm_weight, vae_weight = 0.6, 0.4
    ensemble_0_100 = (lstm_weight * lstm_score + vae_weight * vae_score) * 100.0
    assert 0.0 <= ensemble_0_100 <= 100.0
