"""Unit tests for the torch-backed detectors (LSTM autoencoder + VAE).

torch is not installed locally, so the whole module skips cleanly there via
``pytest.importorskip``. In CI (with torch) these assert the forward-pass shapes
and that the calibrated anomaly scores stay in ``[0, 1]``.
"""

from __future__ import annotations

import pytest

from behaveguard.features.extractor import FeatureExtractor

# Skip the entire module unless torch is importable.
torch = pytest.importorskip("torch")

from behaveguard.models.autoencoder import BehaviorAutoencoder  # noqa: E402
from behaveguard.models.lstm_detector import LSTMDetector  # noqa: E402

D = FeatureExtractor.NUM_FEATURES  # 427


def test_lstm_forward_shapes():
    """LSTM forward returns (recon (B,S,D), hidden (B,hidden_dim))."""
    batch, seq = 2, 5
    hidden_dim = 32
    model = LSTMDetector(
        input_dim=D, hidden_dim=hidden_dim, num_layers=2, sequence_length=seq
    )
    model.eval()
    x = torch.rand(batch, seq, D)

    recon, hidden = model(x)

    assert tuple(recon.shape) == (batch, seq, D)
    assert tuple(hidden.shape) == (batch, hidden_dim)


def test_lstm_reconstruction_error_shape_and_score_range():
    """Per-sample error is shape (B,); anomaly_score is a float in [0,1]."""
    batch, seq = 2, 5
    model = LSTMDetector(input_dim=D, hidden_dim=16, num_layers=1, sequence_length=seq)
    x = torch.rand(batch, seq, D)

    error = model.reconstruction_error(x)
    assert tuple(error.shape) == (batch,)

    score = model.anomaly_score(x)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_lstm_accepts_single_unbatched_sequence():
    """A 2-D (S, D) sequence is promoted to a batch of one for scoring."""
    seq = 5
    model = LSTMDetector(input_dim=D, hidden_dim=16, num_layers=1, sequence_length=seq)
    x = torch.rand(seq, D)

    error = model.reconstruction_error(x)
    assert tuple(error.shape) == (1,)
    assert 0.0 <= model.anomaly_score(x) <= 1.0


def test_vae_forward_shapes():
    """VAE forward returns (recon (B,D), mu (B,latent), logvar (B,latent))."""
    batch = 2
    latent_dim = 8
    model = BehaviorAutoencoder(input_dim=D, latent_dim=latent_dim)
    model.eval()
    x = torch.rand(batch, D)

    recon, mu, logvar = model(x)

    assert tuple(recon.shape) == (batch, D)
    assert tuple(mu.shape) == (batch, latent_dim)
    assert tuple(logvar.shape) == (batch, latent_dim)
    # Decoder ends in a sigmoid -> reconstruction lives in [0, 1].
    assert float(recon.min()) >= 0.0
    assert float(recon.max()) <= 1.0


def test_vae_reconstruction_error_shape_and_score_range():
    """Per-sample error is shape (B,); anomaly_score is a float in [0,1]."""
    batch = 4
    model = BehaviorAutoencoder(input_dim=D, latent_dim=8)
    x = torch.rand(batch, D)

    error = model.reconstruction_error(x)
    assert tuple(error.shape) == (batch,)

    score = model.anomaly_score(x)
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0


def test_vae_loss_components_are_finite_scalars():
    """The VAE loss returns finite (total, recon, kld) scalars with total == sum."""
    batch = 3
    model = BehaviorAutoencoder(input_dim=D, latent_dim=8)
    x = torch.rand(batch, D)
    recon, mu, logvar = model(x)

    total, recon_loss, kld = model.loss_function(recon, x, mu, logvar)

    for t in (total, recon_loss, kld):
        assert t.dim() == 0
        assert torch.isfinite(t)
    assert float(total) == pytest.approx(float(recon_loss) + float(kld), rel=1e-5)


def test_set_baseline_floors_zero_std():
    """A zero/negative std is floored to a small positive value to stay stable."""
    model = BehaviorAutoencoder(input_dim=D, latent_dim=8)
    model.set_baseline(mean=0.5, std=0.0)
    assert float(model.baseline_std) > 0.0
    # Scoring must still produce a bounded float, not NaN/inf.
    score = model.anomaly_score(torch.rand(2, D))
    assert 0.0 <= score <= 1.0
