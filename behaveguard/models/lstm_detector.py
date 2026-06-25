"""LSTM sequence autoencoder for behavioral anomaly detection.

The detector learns the *normal* temporal structure of a process by
reconstructing sequences of per-window feature vectors. At inference time a
sequence that the model reconstructs poorly (high MSE relative to the learned
baseline) yields a high anomaly score.

Architecture (sequence-to-sequence autoencoder):

* **Encoder** — a multi-layer :class:`torch.nn.LSTM` consumes the input sequence
  ``(B, S, input_dim)`` and the final hidden state of its last layer is taken as
  a fixed-size latent summary ``(B, hidden_dim)``.
* **Decoder** — the latent vector is repeated across all ``S`` time steps and fed
  to a second :class:`torch.nn.LSTM`, whose outputs are projected back to the
  feature space by a linear layer, producing the reconstruction
  ``(B, S, input_dim)``.

``torch`` is imported at module top level because this file defines
:class:`torch.nn.Module` subclasses; importing it therefore requires torch.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

import torch
from torch import Tensor, nn

from behaveguard.models.base_model import BaseDetector


class LSTMDetector(nn.Module, BaseDetector):
    """Sequence-to-sequence LSTM autoencoder over per-window feature vectors."""

    model_type: str = "lstm"

    def __init__(
        self,
        input_dim: int,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
        sequence_length: int = 20,
    ) -> None:
        """Build the encoder/decoder/projection stack.

        Args:
            input_dim: Dimensionality of each per-window feature vector.
            hidden_dim: LSTM hidden size, also the latent dimensionality.
            num_layers: Number of stacked LSTM layers in encoder and decoder.
            dropout: Inter-layer dropout (applied by ``nn.LSTM`` only when
                ``num_layers > 1``).
            sequence_length: Nominal sequence length used when building training
                sequences; stored for config reconstruction.
        """
        super().__init__()
        self.input_dim = int(input_dim)
        self.hidden_dim = int(hidden_dim)
        self.num_layers = int(num_layers)
        self.dropout = float(dropout)
        self.sequence_length = int(sequence_length)

        # nn.LSTM only applies dropout between stacked layers; with a single
        # layer it must be 0.0 (and torch warns otherwise).
        lstm_dropout = self.dropout if self.num_layers > 1 else 0.0

        self.encoder = nn.LSTM(
            input_size=self.input_dim,
            hidden_size=self.hidden_dim,
            num_layers=self.num_layers,
            batch_first=True,
            dropout=lstm_dropout,
        )
        self.decoder = nn.LSTM(
            input_size=self.hidden_dim,
            hidden_size=self.hidden_dim,
            num_layers=self.num_layers,
            batch_first=True,
            dropout=lstm_dropout,
        )
        self.output_projection = nn.Linear(self.hidden_dim, self.input_dim)

        # Baseline reconstruction-error statistics learned from normal validation
        # data. Registered as buffers so they move with the model and persist in
        # the checkpoint, without being treated as trainable parameters.
        self.register_buffer("baseline_mean", torch.tensor(0.0))
        self.register_buffer("baseline_std", torch.tensor(1.0))

    # ------------------------------------------------------------------ #
    # Baseline calibration
    # ------------------------------------------------------------------ #
    def set_baseline(self, mean: float, std: float) -> None:
        """Set the baseline reconstruction-error mean/std used for scoring.

        Args:
            mean: Mean per-sample reconstruction error over normal data.
            std: Standard deviation of that error (clamped to a small positive
                floor to avoid divide-by-zero at score time).
        """
        safe_std = float(std)
        if safe_std <= 0.0:
            safe_std = 1e-6
        self.baseline_mean = torch.tensor(float(mean))
        self.baseline_std = torch.tensor(safe_std)

    # ------------------------------------------------------------------ #
    # Forward / reconstruction
    # ------------------------------------------------------------------ #
    def forward(self, x: Tensor) -> Tuple[Tensor, Tensor]:
        """Encode then decode a batch of sequences.

        Args:
            x: Input tensor of shape ``(B, S, input_dim)``.

        Returns:
            ``(reconstruction, hidden)`` where ``reconstruction`` has shape
            ``(B, S, input_dim)`` and ``hidden`` is the latent summary
            ``(B, hidden_dim)`` (the last layer's final hidden state).
        """
        batch_size, seq_len, _ = x.shape

        # Encode: take the final hidden state of the last layer as the latent.
        _, (h_n, _c_n) = self.encoder(x)
        latent = h_n[-1]  # (B, hidden_dim)

        # Decode: broadcast the latent across every time step.
        decoder_input = latent.unsqueeze(1).repeat(1, seq_len, 1)  # (B, S, hidden_dim)
        decoded, _ = self.decoder(decoder_input)
        reconstruction = self.output_projection(decoded)  # (B, S, input_dim)
        return reconstruction, latent

    def reconstruction_error(self, x: Tensor) -> Tensor:
        """Per-sample mean-squared reconstruction error.

        Accepts a single sequence ``(S, input_dim)`` or a batch
        ``(B, S, input_dim)``; a 2-D input is promoted to a batch of one.

        Args:
            x: Input sequence or batch of sequences.

        Returns:
            A 1-D tensor of shape ``(B,)`` holding the mean MSE over the
            ``(S, input_dim)`` axes for each sample.
        """
        if x.dim() == 2:
            x = x.unsqueeze(0)
        reconstruction, _ = self.forward(x)
        # Mean over the (sequence, feature) dimensions -> one error per sample.
        per_element = (reconstruction - x) ** 2
        return per_element.mean(dim=(1, 2))

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def anomaly_score(self, x: Tensor) -> float:
        """Calibrated anomaly score in ``[0, 1]`` (mean over the batch).

        The raw reconstruction error is standardized against the learned baseline
        and squashed through a sigmoid, so the output is always bounded.

        Args:
            x: Input sequence ``(S, input_dim)`` or batch ``(B, S, input_dim)``.

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
        return {
            "input_dim": self.input_dim,
            "hidden_dim": self.hidden_dim,
            "num_layers": self.num_layers,
            "dropout": self.dropout,
            "sequence_length": self.sequence_length,
        }
