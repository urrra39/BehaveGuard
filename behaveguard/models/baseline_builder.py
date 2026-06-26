"""Training pipeline that builds per-process behavioral baselines.

A "baseline" is the bundle of models that captures what *normal* looks like for a
given process type: a :class:`BehaviorAutoencoder` over single feature windows, an
:class:`LSTMDetector` over sequences of windows, a fitted
:class:`~behaveguard.features.normalizer.FeatureNormalizer`, and a tuned anomaly
threshold. :class:`BaselineBuilder` turns recorded "normal" event sessions into
that bundle and persists it through :class:`~behaveguard.models.model_store.ModelStore`.

``torch`` is imported at module top level (training requires it). This module is
therefore only importable on a host with the deep-learning stack installed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence

import torch
from torch import Tensor, nn
from torch.utils.data import DataLoader, TensorDataset

from behaveguard.collector.event_types import RawEvent
from behaveguard.features.extractor import FeatureExtractor
from behaveguard.features.normalizer import FeatureNormalizer
from behaveguard.models.autoencoder import BehaviorAutoencoder
from behaveguard.models.lstm_detector import LSTMDetector
from behaveguard.models.model_store import ModelStore
from behaveguard.models.threshold_tuner import ThresholdTuner

if TYPE_CHECKING:  # pragma: no cover - typing only
    from behaveguard.config.settings import Settings


@dataclass
class TrainingResult:
    """Summary metrics returned by :meth:`BaselineBuilder.train`."""

    process_name: str
    epochs_run: int
    train_loss: float
    val_loss: float
    threshold: float
    num_sequences: int
    num_windows: int
    lstm_trained: bool
    vae_trained: bool


class BaselineBuilder:
    """Trains and persists per-process baseline model bundles."""

    def __init__(self, config: "Settings", model_store: Optional[ModelStore] = None) -> None:
        self.config = config
        self.model_store = model_store if model_store is not None else ModelStore()
        self.extractor = FeatureExtractor(window_seconds=config.features.window_seconds)
        self.tuner = ThresholdTuner()
        self.device = torch.device("cpu")

        self.window_seconds = int(config.features.window_seconds)
        self.sequence_length = int(config.features.sequence_length)
        self.input_dim = FeatureExtractor.NUM_FEATURES

    # ------------------------------------------------------------------ #
    # Feature / sequence construction
    # ------------------------------------------------------------------ #
    def _session_to_windows(self, events: Sequence[RawEvent]) -> List[List[float]]:
        """Slide a window across one session's events, yielding feature vectors.

        Windows of ``window_seconds`` advance by half a window (50% overlap). A
        session shorter than one window still produces a single vector.
        """
        if not events:
            return []

        ordered = sorted(events, key=lambda e: int(e.timestamp_ns))
        start_ns = int(ordered[0].timestamp_ns)
        end_ns = int(ordered[-1].timestamp_ns)
        window_ns = self.window_seconds * 1_000_000_000
        stride_ns = max(window_ns // 2, 1)

        windows: List[List[float]] = []
        cursor = start_ns
        idx = 0
        while cursor <= end_ns:
            upper = cursor + window_ns
            bucket = [e for e in ordered if cursor <= int(e.timestamp_ns) < upper]
            if bucket:
                windows.append(self.extractor.extract_vector(bucket, self.window_seconds))
            cursor += stride_ns
            idx += 1
            # Guard against pathological all-equal timestamps producing one window.
            if start_ns == end_ns:
                break

        if not windows:
            windows.append(self.extractor.extract_vector(ordered, self.window_seconds))
        return windows

    def _build_sequences(self, session_windows: List[List[List[float]]]) -> List[List[List[float]]]:
        """Build fixed-length LSTM sequences from per-session window lists.

        Within each session, a sliding window of length ``sequence_length`` (step
        1) produces sequences. Sessions with fewer windows than
        ``sequence_length`` are front-padded by repeating their first window so
        they still contribute exactly one sequence.
        """
        seq_len = self.sequence_length
        sequences: List[List[List[float]]] = []
        for windows in session_windows:
            if not windows:
                continue
            if len(windows) < seq_len:
                pad = [windows[0]] * (seq_len - len(windows))
                sequences.append(pad + list(windows))
            else:
                for i in range(len(windows) - seq_len + 1):
                    sequences.append(list(windows[i : i + seq_len]))
        return sequences

    # ------------------------------------------------------------------ #
    # Training primitives
    # ------------------------------------------------------------------ #
    @staticmethod
    def _split(n: int, validation_split: float) -> int:
        """Return the size of the training partition for ``n`` items."""
        val = int(round(n * validation_split))
        val = min(max(val, 1 if n > 1 else 0), n - 1 if n > 1 else 0)
        return n - val

    def _train_vae(
        self,
        windows: Tensor,
        epochs: int,
        patience: int,
        batch_size: int,
        lr: float,
    ) -> "tuple[BehaviorAutoencoder, float, float, int, List[float]]":
        """Train the VAE with early stopping; return model, losses, and val errors."""
        n = windows.shape[0]
        n_train = self._split(n, self.config_validation_split)
        train_x, val_x = windows[:n_train], windows[n_train:]

        model = BehaviorAutoencoder(self.input_dim, self.config.models.latent_dim).to(self.device)
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        loader = DataLoader(TensorDataset(train_x), batch_size=batch_size, shuffle=True)

        best_val = float("inf")
        best_state = model.state_dict()
        epochs_no_improve = 0
        last_train_loss = 0.0
        epochs_run = 0

        for epoch in range(epochs):
            epochs_run = epoch + 1
            model.train()
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon, mu, logvar = model(batch)
                total, _recon, _kld = BehaviorAutoencoder.loss_function(recon, batch, mu, logvar)
                total.backward()
                optimizer.step()
                epoch_loss += float(total.item())
            last_train_loss = epoch_loss / max(len(loader), 1)

            val_loss = self._vae_val_loss(model, val_x)
            if val_loss < best_val - 1e-6:
                best_val = val_loss
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    break

        model.load_state_dict(best_state)
        val_errors = self._per_sample_errors(model, val_x)
        return model, last_train_loss, best_val, epochs_run, val_errors

    @staticmethod
    def _vae_val_loss(model: BehaviorAutoencoder, val_x: Tensor) -> float:
        if val_x.shape[0] == 0:
            return float("inf")
        model.eval()
        with torch.no_grad():
            recon, mu, logvar = model(val_x)
            total, _r, _k = BehaviorAutoencoder.loss_function(recon, val_x, mu, logvar)
            return float(total.item())

    def _train_lstm(
        self,
        sequences: Tensor,
        epochs: int,
        patience: int,
        batch_size: int,
        lr: float,
    ) -> "tuple[LSTMDetector, float, float, int, List[float]]":
        """Train the LSTM autoencoder with early stopping."""
        n = sequences.shape[0]
        n_train = self._split(n, self.config_validation_split)
        train_x, val_x = sequences[:n_train], sequences[n_train:]

        model = LSTMDetector(
            self.input_dim,
            hidden_dim=self.config.models.hidden_dim,
            num_layers=self.config.models.num_lstm_layers,
            sequence_length=self.sequence_length,
        ).to(self.device)
        optimizer = torch.optim.Adam(model.parameters(), lr=lr)
        criterion = nn.MSELoss()
        loader = DataLoader(TensorDataset(train_x), batch_size=batch_size, shuffle=True)

        best_val = float("inf")
        best_state = model.state_dict()
        epochs_no_improve = 0
        last_train_loss = 0.0
        epochs_run = 0

        for epoch in range(epochs):
            epochs_run = epoch + 1
            model.train()
            epoch_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon, _hidden = model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                optimizer.step()
                epoch_loss += float(loss.item())
            last_train_loss = epoch_loss / max(len(loader), 1)

            val_loss = self._lstm_val_loss(model, criterion, val_x)
            if val_loss < best_val - 1e-6:
                best_val = val_loss
                best_state = {k: v.clone() for k, v in model.state_dict().items()}
                epochs_no_improve = 0
            else:
                epochs_no_improve += 1
                if epochs_no_improve >= patience:
                    break

        model.load_state_dict(best_state)
        val_errors = self._per_sample_errors(model, val_x)
        return model, last_train_loss, best_val, epochs_run, val_errors

    @staticmethod
    def _lstm_val_loss(model: LSTMDetector, criterion: nn.Module, val_x: Tensor) -> float:
        if val_x.shape[0] == 0:
            return float("inf")
        model.eval()
        with torch.no_grad():
            recon, _hidden = model(val_x)
            return float(criterion(recon, val_x).item())

    @staticmethod
    def _per_sample_errors(model: object, val_x: Tensor) -> List[float]:
        """Per-sample reconstruction errors on a validation tensor (as floats)."""
        if val_x.shape[0] == 0:
            return []
        with torch.no_grad():
            errors = model.reconstruction_error(val_x)  # type: ignore[attr-defined]
        return [float(e) for e in errors.tolist()]

    # ------------------------------------------------------------------ #
    # Public training API
    # ------------------------------------------------------------------ #
    def train(
        self,
        process_name: str,
        training_events: List[List[RawEvent]],
        validation_split: float = 0.2,
        epochs: int = 100,
        early_stopping_patience: int = 10,
    ) -> TrainingResult:
        """Train a full baseline bundle for ``process_name`` and persist it.

        Args:
            process_name: Logical process name (``comm``) for the bundle.
            training_events: One inner list of events per observed normal session.
            validation_split: Fraction of windows/sequences held out for
                validation, early stopping, and threshold tuning.
            epochs: Maximum training epochs per model.
            early_stopping_patience: Stop after this many epochs without
                validation improvement.

        Returns:
            A :class:`TrainingResult` describing the trained bundle.

        Raises:
            ValueError: If no usable feature windows could be built.
        """
        self.config_validation_split = float(validation_split)

        session_windows = [self._session_to_windows(s) for s in training_events]
        session_windows = [w for w in session_windows if w]
        all_windows = [vec for windows in session_windows for vec in windows]
        if not all_windows:
            raise ValueError(f"no feature windows could be built for {process_name!r}")

        sequences = self._build_sequences(session_windows)

        # Fit and apply the normalizer (kept in sync between train and inference).
        normalizer = FeatureNormalizer().fit(all_windows)
        norm_windows = [normalizer.transform_minmax(v).tolist() for v in all_windows]
        norm_sequences = [
            [normalizer.transform_minmax(v).tolist() for v in seq] for seq in sequences
        ]

        windows_tensor = torch.tensor(norm_windows, dtype=torch.float32, device=self.device)
        batch_size = int(self.config.models.batch_size)
        lr = float(self.config.models.learning_rate)

        vae, vae_train_loss, vae_val_loss, vae_epochs, vae_val_errors = self._train_vae(
            windows_tensor, epochs, early_stopping_patience, batch_size, lr
        )
        if vae_val_errors:
            vae.set_baseline(
                self.tuner._mean(vae_val_errors),
                self.tuner._std(vae_val_errors, self.tuner._mean(vae_val_errors)),
            )

        lstm: Optional[LSTMDetector] = None
        lstm_epochs = 0
        lstm_val_loss = float("inf")
        lstm_train_loss = 0.0
        if norm_sequences:
            sequences_tensor = torch.tensor(norm_sequences, dtype=torch.float32, device=self.device)
            lstm, lstm_train_loss, lstm_val_loss, lstm_epochs, lstm_val_errors = self._train_lstm(
                sequences_tensor, epochs, early_stopping_patience, batch_size, lr
            )
            if lstm_val_errors:
                mean = self.tuner._mean(lstm_val_errors)
                lstm.set_baseline(mean, self.tuner._std(lstm_val_errors, mean))

        # Threshold from VAE validation errors (mean + n*std, FPR-bounded).
        threshold = self.tuner.tune_from_errors(vae_val_errors, n_std=2.0, target_fpr=0.05)

        metadata = {
            "input_dim": self.input_dim,
            "window_seconds": self.window_seconds,
            "sequence_length": self.sequence_length,
            "threshold": threshold,
            "vae_val_loss": vae_val_loss,
            "lstm_val_loss": lstm_val_loss if lstm is not None else None,
            "num_windows": len(all_windows),
            "num_sequences": len(sequences),
            "epochs": {"vae": vae_epochs, "lstm": lstm_epochs},
        }
        self.model_store.save(process_name, lstm, vae, normalizer, metadata)

        return TrainingResult(
            process_name=process_name,
            epochs_run=max(vae_epochs, lstm_epochs),
            train_loss=vae_train_loss,
            val_loss=vae_val_loss,
            threshold=threshold,
            num_sequences=len(sequences),
            num_windows=len(all_windows),
            lstm_trained=lstm is not None,
            vae_trained=True,
        )

    def train_from_running_processes(
        self, observation_minutes: int = 60
    ) -> Dict[str, TrainingResult]:
        """Observe live processes for a while, treat that as normal, and train.

        Behavior during the observation window is assumed benign; one baseline is
        trained per distinct process ``comm`` seen.

        Args:
            observation_minutes: How long to collect events before training.

        Returns:
            A mapping of process name to its :class:`TrainingResult`.
        """
        import asyncio

        events_by_comm = asyncio.run(self._observe(observation_minutes))
        results: Dict[str, TrainingResult] = {}
        for comm, events in events_by_comm.items():
            if not events:
                continue
            try:
                results[comm] = self.train(comm, [events])
            except ValueError:
                # Not enough signal for this process; skip it.
                continue
        return results

    async def _observe(self, observation_minutes: int) -> Dict[str, List[RawEvent]]:
        """Collect live events for ``observation_minutes``, grouped by ``comm``."""
        from behaveguard.collector.ebpf_collector import EBPFCollector

        collector = EBPFCollector(self.config)
        await collector.start()
        events_by_comm: Dict[str, List[RawEvent]] = {}
        deadline = time.monotonic() + observation_minutes * 60
        try:
            async for event in collector.events():
                events_by_comm.setdefault(event.comm, []).append(event)
                if time.monotonic() >= deadline:
                    break
        finally:
            await collector.stop()
        return events_by_comm
