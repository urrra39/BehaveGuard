"""Versioned registry of trained baseline models.

A small JSON document (default ``~/.behaveguard/models/registry.json``) records,
per process, an append-only list of trained model versions with their metrics and
on-disk location. Writes are atomic (temp file + ``os.replace``) so a crash mid-
write cannot corrupt the registry. Pure standard library — imports anywhere.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ModelVersion:
    """One recorded version of a process's trained baseline."""

    process_name: str
    version: int
    path: str
    created_unix: float
    metrics: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""


class ModelRegistry:
    """Tracks versions of trained baseline models in a JSON document."""

    def __init__(self, registry_path: Optional[str] = None) -> None:
        if registry_path is not None:
            self.registry_path = Path(registry_path)
        else:
            self.registry_path = Path.home() / ".behaveguard" / "models" / "registry.json"

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def _load(self) -> Dict[str, List[Dict[str, Any]]]:
        if not self.registry_path.is_file():
            return {}
        try:
            with self.registry_path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, data: Dict[str, List[Dict[str, Any]]]) -> None:
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.registry_path.with_suffix(self.registry_path.suffix + ".tmp")
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(tmp_path, self.registry_path)

    # ------------------------------------------------------------------ #
    # API
    # ------------------------------------------------------------------ #
    def register(
        self,
        process_name: str,
        metrics: Optional[Dict[str, Any]] = None,
        path: Optional[str] = None,
        notes: str = "",
    ) -> int:
        """Append a new version for ``process_name`` and return its version number.

        Args:
            process_name: Process whose baseline was (re)trained.
            metrics: Training metrics to record (threshold, val loss, etc.).
            path: On-disk location of the model bundle.
            notes: Optional free-form note.

        Returns:
            The newly assigned, monotonically increasing version number.
        """
        data = self._load()
        versions = data.setdefault(process_name, [])
        next_version = (versions[-1]["version"] + 1) if versions else 1
        entry = ModelVersion(
            process_name=process_name,
            version=next_version,
            path=path or "",
            created_unix=time.time(),
            metrics=dict(metrics or {}),
            notes=notes,
        )
        versions.append(asdict(entry))
        self._save(data)
        return next_version

    def get_latest(self, process_name: str) -> Optional[Dict[str, Any]]:
        """Return the most recent version record for ``process_name`` (or ``None``)."""
        versions = self._load().get(process_name, [])
        return versions[-1] if versions else None

    def list_versions(self, process_name: str) -> List[Dict[str, Any]]:
        """Return all version records for ``process_name`` (oldest first)."""
        return list(self._load().get(process_name, []))

    def list_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return the entire registry mapping of process name to versions."""
        return self._load()
