"""Variational autoencoder over single behavioral feature windows.

Where the LSTM models *temporal* structure across a sequence of windows, this
VAE models the structure of a *single* window's feature vector. It learns a
compact latent distribution of normal behavior; windows that reconstruct poorly
(relative to the learned baseline) are scored as anomalous.

All input features are assumed to live in ``[0, 1]`` (the feature extractor and
normalizer both clamp to that range), so the decoder ends in a sigmoid.

``torch`` is imported at module top level because this file defines a
:class:`torch.nn.Module` subclass.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import torch
from torch import Tensor, nn

from behaveguard.models.base_model import BaseDetector


class BehaviorAutoencoder(nn.Module, BaseDetector):
    """A small VAE that reconstructs single feature windows in ``[0, 1]``."""

    model_type: str = "vae"

    def __init__(self, input_dim: int, latent_dim: int = 32) -> None:
        """Build the encoder MLP, latent heads, and decoder MLP.

        Args:
            input_dim: Dimensionality of a single feature window.
            latent_dim: Size of the latent (bottleneck) representation.
        """
        super().__init__()
        self.input_dim = int(input_dim)
        self.latent_dim = int(latent_dim)

        # Encoder: input_dim -> 512 -> 256 -> 128 (shared trunk).
        self.encoder = nn.Sequential(
            nn.Linear(self.input_dim, 512),
            nn.ReLU(),
            nn.Linear(512, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
        )
        # Latent distribution heads.
        self.fc_mu = nn.Linear(128, self.latent_dim)
        self.fc_logvar = nn.Linear(128, self.latent_dim)

        # Decoder: latent_dim -> 128 -> 256 -> 512 -> input_dim, sigmoid output.
        self.decoder = nn.Sequential(
            nn.Linear(self.latent_dim, 128),
            nn.ReLU(),
            nn.Linear(128, 256),
            nn.ReLU(),
            nn.Linear(256, 512),
            nn.ReLU(),
            nn.Linear(512, self.input_dim),
            nn.Sigmoid(),
        )

        # Baseline reconstruction-error statistics from normal validation data.
        self.register_buffer("baseline_mean", torch.tensor(0.0))
        self.register_buffer("baseline_std", torch.tensor(1.0))

    # ------------------------------------------------------------------ #
    # Baseline calibration
    # ------------------------------------------------------------------ #
    def set_baseline(self, mean: float, std: float) -> None:
        """Set the baseline reconstruction-error mean/std used for scoring.

        Args:
            mean: Mean per-sample reconstruction error over normal data.
            std: Standard deviation of that error (floored to a small positive
                value to keep scoring numerically stable).
        """
        safe_std = float(std)
        if safe_std <= 0.0:
            safe_std = 1e-6
        self.baseline_mean = torch.tensor(float(mean))
        self.baseline_std = torch.tensor(safe_std)

    # ------------------------------------------------------------------ #
    # VAE primitives
    # ------------------------------------------------------------------ #
    def encode(self, x: Tensor) -> Tuple[Tensor, Tensor]:
        """Encode an input batch into latent ``(mu, logvar)``.

        Args:
            x: Input of shape ``(B, input_dim)`` or ``(input_dim,)``.

        Returns:
            ``(mu, logvar)`` each of shape ``(B, latent_dim)``.
        """
        if x.dim() == 1:
            x = x.unsqueeze(0)
        hidden = self.encoder(x)
        return self.fc_mu(hidden), self.fc_logvar(hidden)

    def reparameterize(self, mu: Tensor, logvar: Tensor) -> Tensor:
        """Sample ``z`` from ``N(mu, sigma^2)`` via the reparameterization trick.

        Args:
            mu: Latent means ``(B, latent_dim)``.
            logvar: Latent log-variances ``(B, latent_dim)``.

        Returns:
            A latent sample ``z = mu + eps * std`` of shape ``(B, latent_dim)``.
        """
        std = torch.exp(0.5 * logvar)
        eps = torch.randn_like(std)
        return mu + eps * std

    def decode(self, z: Tensor) -> Tensor:
        """Decode a latent sample back into feature space.

        Args:
            z: Latent batch ``(B, latent_dim)``.

        Returns:
            Reconstruction ``(B, input_dim)`` with values in ``[0, 1]``.
        """
        return self.decoder(z)

    def forward(self, x: Tensor) -> Tuple[Tensor, Tensor, Tensor]:
        """Full VAE forward pass.

        Accepts a single window ``(input_dim,)`` or a batch ``(B, input_dim)``.

        Args:
            x: Input window or batch of windows.

        Returns:
            ``(reconstruction, mu, logvar)``; ``reconstruction`` is
            ``(B, input_dim)`` and the latent stats are ``(B, latent_dim)``.
        """
        if x.dim() == 1:
            x = x.unsqueeze(0)
        mu, logvar = self.encode(x)
        z = self.reparameterize(mu, logvar)
        reconstruction = self.decode(z)
        return reconstruction, mu, logvar

    # ------------------------------------------------------------------ #
    # Loss
    # ------------------------------------------------------------------ #
    @staticmethod
    def loss_function(
        recon: Tensor, x: Tensor, mu: Tensor, logvar: Tensor
    ) -> Tuple[Tensor, Tensor, Tensor]:
        """Standard VAE loss: reconstruction MSE plus KL divergence.

        The reconstruction term is the per-sample summed squared error averaged
        over the batch; the KLD term is the closed-form divergence between the
        latent posterior and a unit Gaussian.

        Args:
            recon: Reconstruction ``(B, input_dim)``.
            x: Original input ``(B, input_dim)``.
            mu: Latent means ``(B, latent_dim)``.
            logvar: Latent log-variances ``(B, latent_dim)``.

        Returns:
            ``(total, recon_loss, kld)`` scalar tensors with
            ``total = recon_loss + kld``.
        """
        if x.dim() == 1:
            x = x.unsqueeze(0)
        batch_size = x.shape[0]

        # Sum squared error per sample, then mean across the batch.
        recon_loss = ((recon - x) ** 2).sum(dim=1).mean()

        # KL divergence between N(mu, sigma^2) and N(0, I), summed over latent
        # dims and the batch, then normalized by batch size to match recon scale.
        kld = -0.5 * torch.sum(1.0 + logvar - mu.pow(2) - logvar.exp())
        kld = kld / float(batch_size)

        total = recon_loss + kld
        return total, recon_loss, kld

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def reconstruction_error(self, x: Tensor) -> Tensor:
        """Per-sample mean-squared reconstruction error (no KLD term).

        Accepts a single window ``(input_dim,)`` or a batch ``(B, input_dim)``.

        Args:
            x: Input window or batch.

        Returns:
            A 1-D tensor ``(B,)`` of mean squared error per sample.
        """
        if x.dim() == 1:
            x = x.unsqueeze(0)
        reconstruction, _mu, _logvar = self.forward(x)
        return ((reconstruction - x) ** 2).mean(dim=1)

    def anomaly_score(self, x: Tensor) -> float:
        """Calibrated anomaly score in ``[0, 1]`` (mean over the batch).

        Uses the reconstruction error only (not the KLD), standardized against
        the learned baseline and squashed through a sigmoid.

        Args:
            x: Input window ``(input_dim,)`` or batch ``(B, input_dim)``.

        Returns:
            Mean squashed anomaly score across the batch as a python ``float``.
        """
        self.eval()
        with torch.no_grad():
            error = self.reconstruction_error(x)  # (B,)
            z = (error - self.baseline_mean) / self.baseline_std
            squashed = torch.sigmoid(z)
            return float(squashed.mean().item())

    # ------------------------------------------------------------------ #
    # Reconstruction config
    # ------------------------------------------------------------------ #
    def get_config(self) -> Dict[str, Any]:
        """Constructor kwargs needed to rebuild this model from a checkpoint."""
        return {"input_dim": self.input_dim, "latent_dim": self.latent_dim}
