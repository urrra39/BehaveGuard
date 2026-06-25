"""On-disk store for per-process model bundles.

Each monitored process gets its own directory holding up to three artifacts —
the LSTM checkpoint, the VAE checkpoint, and the fitted feature normalizer —
alongside a ``metadata.json`` describing what was saved and when.

This module is **import-safe without torch**: the torch-dependent model classes
and :class:`~behaveguard.features.normalizer.FeatureNormalizer` are imported
lazily inside the methods that actually need them. Listing, checking existence,
and deleting bundles therefore work with nothing but the standard library.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ModelNotFoundError(Exception):
    """Raised when a requested per-process model bundle does not exist."""


class ModelStore:
    """Persists and retrieves per-process ``(lstm, vae, normalizer, metadata)`` bundles."""

    #: Default root under which every process's bundle directory lives.
    BASE_DIR: Path = Path.home() / ".behaveguard" / "models"

    #: Standard artifact filenames within a bundle directory.
    LSTM_FILE = "lstm.pt"
    VAE_FILE = "vae.pt"
    NORMALIZER_FILE = "normalizer.pkl"
    METADATA_FILE = "metadata.json"

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        """Create a store rooted at ``base_dir`` (defaults to :attr:`BASE_DIR`).

        Args:
            base_dir: Override for the storage root, useful for tests and custom
                deployments. The directory is created lazily on first save.
        """
        self.base_dir: Path = Path(base_dir) if base_dir is not None else self.BASE_DIR

    # ------------------------------------------------------------------ #
    # Path helpers
    # ------------------------------------------------------------------ #
    def _process_dir(self, process_name: str) -> Path:
        """Return the bundle directory for ``process_name``."""
        return self.base_dir / process_name

    # ------------------------------------------------------------------ #
    # Save / load
    # ------------------------------------------------------------------ #
    def save(
        self,
        process_name: str,
        lstm: Optional[Any],
        vae: Optional[Any],
        normalizer: Optional[Any],
        metadata: Dict[str, Any],
    ) -> None:
        """Persist a model bundle for ``process_name``.

        Any of ``lstm``/``vae``/``normalizer`` may be ``None`` to skip that
        artifact. A ``metadata.json`` is always written, augmented with per-artifact
        ``saved`` flags and a ``saved_at`` UNIX timestamp.

        Args:
            process_name: Logical name (process ``comm``) keying the bundle.
            lstm: A trained LSTM detector (with a ``.save(path)`` method) or ``None``.
            vae: A trained VAE detector (with a ``.save(path)`` method) or ``None``.
            normalizer: A fitted ``FeatureNormalizer`` (with ``.save(path)``) or ``None``.
            metadata: Arbitrary JSON-serializable training metadata to record.
        """
        target_dir = self._process_dir(process_name)
        target_dir.mkdir(parents=True, exist_ok=True)

        lstm_saved = False
        if lstm is not None:
            lstm.save(str(target_dir / self.LSTM_FILE))
            lstm_saved = True

        vae_saved = False
        if vae is not None:
            vae.save(str(target_dir / self.VAE_FILE))
            vae_saved = True

        normalizer_saved = False
        if normalizer is not None:
            normalizer.save(str(target_dir / self.NORMALIZER_FILE))
            normalizer_saved = True

        full_metadata: Dict[str, Any] = dict(metadata)
        full_metadata.update(
            {
                "process_name": process_name,
                "lstm_saved": lstm_saved,
                "vae_saved": vae_saved,
                "normalizer_saved": normalizer_saved,
                "saved_at": time.time(),
            }
        )
        with (target_dir / self.METADATA_FILE).open("w", encoding="utf-8") as handle:
            json.dump(full_metadata, handle, indent=2, sort_keys=True)

    def load(
        self, process_name: str
    ) -> Tuple[Optional[Any], Optional[Any], Optional[Any], Dict[str, Any]]:
        """Load a previously saved bundle for ``process_name``.

        Torch model classes and the feature normalizer are imported lazily here,
        so importing this module never requires torch.

        Args:
            process_name: The bundle key to load.

        Returns:
            ``(lstm, vae, normalizer, metadata)``. Missing artifacts come back as
            ``None``; ``metadata`` is the parsed ``metadata.json``.

        Raises:
            ModelNotFoundError: If the bundle directory or its metadata is absent.
        """
        target_dir = self._process_dir(process_name)
        metadata_path = target_dir / self.METADATA_FILE
        if not target_dir.is_dir() or not metadata_path.is_file():
            raise ModelNotFoundError(
                "no model bundle for process {0!r} under {1}".format(
                    process_name, self.base_dir
                )
            )

        with metadata_path.open("r", encoding="utf-8") as handle:
            metadata: Dict[str, Any] = json.load(handle)

        # Lazy imports keep the module torch-free at import time.
        from behaveguard.features.normalizer import FeatureNormalizer
        from behaveguard.models.autoencoder import BehaviorAutoencoder
        from behaveguard.models.lstm_detector import LSTMDetector

        lstm: Optional[Any] = None
        lstm_path = target_dir / self.LSTM_FILE
        if lstm_path.is_file():
            lstm = LSTMDetector.load(str(lstm_path))

        vae: Optional[Any] = None
        vae_path = target_dir / self.VAE_FILE
        if vae_path.is_file():
            vae = BehaviorAutoencoder.load(str(vae_path))

        normalizer: Optional[Any] = None
        normalizer_path = target_dir / self.NORMALIZER_FILE
        if normalizer_path.is_file():
            normalizer = FeatureNormalizer.load(str(normalizer_path))

        return lstm, vae, normalizer, metadata

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def list_models(self) -> List[Dict[str, Any]]:
        """Return the metadata of every stored bundle.

        Returns:
            A list of parsed ``metadata.json`` dicts, one per process directory
            that contains one. Bundles without readable metadata are skipped.
            An empty list is returned if the store root does not exist yet.
        """
        results: List[Dict[str, Any]] = []
        if not self.base_dir.is_dir():
            return results

        for entry in sorted(self.base_dir.iterdir()):
            if not entry.is_dir():
                continue
            metadata_path = entry / self.METADATA_FILE
            if not metadata_path.is_file():
                continue
            try:
                with metadata_path.open("r", encoding="utf-8") as handle:
                    results.append(json.load(handle))
            except (OSError, json.JSONDecodeError):
                # A corrupt/unreadable bundle should not break enumeration.
                continue
        return results

    def exists(self, process_name: str) -> bool:
        """Return whether a bundle (directory + metadata) exists for ``process_name``."""
        target_dir = self._process_dir(process_name)
        return target_dir.is_dir() and (target_dir / self.METADATA_FILE).is_file()

    def delete(self, process_name: str) -> None:
        """Delete the entire bundle directory for ``process_name``.

        No-op if the bundle does not exist.

        Args:
            process_name: The bundle key to remove.
        """
        target_dir = self._process_dir(process_name)
        if target_dir.is_dir():
            shutil.rmtree(target_dir)
