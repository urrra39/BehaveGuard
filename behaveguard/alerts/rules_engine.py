"""User-defined suppression rules to filter out known false positives.

A rule suppresses alerts for a named process as long as the anomaly score stays
below a ceiling (e.g. "the backup agent legitimately reads many files; suppress
anything under 60"). Rules may carry an expiry. Rules persist to a YAML file
(``~/.behaveguard/rules.yaml`` by default); ``yaml`` is imported lazily so the
module imports without PyYAML present.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class SuppressionRule:
    """A single suppression rule keyed by process name."""

    process_name: str
    reason: str
    max_score_suppress: float = 100.0
    expires_at: Optional[datetime] = None
    created_by: str = "user"

    def is_active(self, now: Optional[datetime] = None) -> bool:
        """True if the rule has not expired."""
        if self.expires_at is None:
            return True
        moment = now or datetime.now(timezone.utc)
        # Compare naive/aware consistently by coercing to naive UTC if needed.
        expires = self.expires_at
        if expires.tzinfo is not None and moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        if expires.tzinfo is None and moment.tzinfo is not None:
            expires = expires.replace(tzinfo=timezone.utc)
        return moment < expires

    def to_dict(self) -> dict:
        return {
            "process_name": self.process_name,
            "reason": self.reason,
            "max_score_suppress": self.max_score_suppress,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SuppressionRule":
        expires = data.get("expires_at")
        return cls(
            process_name=data["process_name"],
            reason=data.get("reason", ""),
            max_score_suppress=float(data.get("max_score_suppress", 100.0)),
            expires_at=datetime.fromisoformat(expires) if expires else None,
            created_by=data.get("created_by", "user"),
        )


class RulesEngine:
    """Evaluates and persists suppression rules."""

    DEFAULT_PATH = Path.home() / ".behaveguard" / "rules.yaml"

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path) if path is not None else self.DEFAULT_PATH
        self._rules: Dict[str, SuppressionRule] = {}

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #
    def should_suppress(self, process_name: str, score: float, pid: Optional[int] = None) -> bool:
        """Return whether an alert for ``process_name`` at ``score`` is suppressed.

        Suppressed when an active rule exists for the process and the score is
        below that rule's ``max_score_suppress`` ceiling. ``pid`` is accepted for
        interface symmetry and future per-PID rules.
        """
        rule = self._rules.get(process_name)
        if rule is None or not rule.is_active():
            return False
        return float(score) < rule.max_score_suppress

    # ------------------------------------------------------------------ #
    # Management
    # ------------------------------------------------------------------ #
    def add_rule(self, rule: SuppressionRule) -> None:
        """Add or replace the rule for ``rule.process_name``."""
        self._rules[rule.process_name] = rule

    def remove_rule(self, process_name: str) -> bool:
        """Remove a rule by process name; return whether one was removed."""
        return self._rules.pop(process_name, None) is not None

    def list_rules(self) -> List[SuppressionRule]:
        """Return all configured rules."""
        return list(self._rules.values())

    def clear_expired(self, now: Optional[datetime] = None) -> int:
        """Drop expired rules; return how many were removed."""
        expired = [name for name, rule in self._rules.items() if not rule.is_active(now)]
        for name in expired:
            del self._rules[name]
        return len(expired)

    # ------------------------------------------------------------------ #
    # Persistence (lazy YAML)
    # ------------------------------------------------------------------ #
    def save(self) -> None:
        """Persist all rules to the YAML file."""
        import yaml

        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"rules": [rule.to_dict() for rule in self._rules.values()]}
        with self.path.open("w", encoding="utf-8") as handle:
            yaml.safe_dump(payload, handle, sort_keys=True)

    def load(self) -> None:
        """Load rules from the YAML file (no-op if the file is absent)."""
        import yaml

        if not self.path.is_file():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        self._rules = {}
        for entry in payload.get("rules", []):
            rule = SuppressionRule.from_dict(entry)
            self._rules[rule.process_name] = rule
