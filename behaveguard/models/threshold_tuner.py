"""Anomaly-threshold tuning and evaluation — pure Python, no torch/numpy.

This module deliberately depends on **nothing** beyond the standard library so it
imports and runs anywhere, including environments without a deep-learning stack.
The one method that touches a torch model (:meth:`ThresholdTuner.tune`) only does
so by calling ``model.reconstruction_error`` at *call* time and converting the
result to a python ``float`` — the module itself never imports torch.

The tuner picks a reconstruction-error threshold from a sample of *normal*
errors, balancing two criteria:

* a parametric ``mean + n_std * std`` cutoff, and
* an empirical ``(1 - target_fpr)`` quantile,

taking the larger of the two so that at most roughly ``target_fpr`` of normal
samples are expected to exceed the threshold.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Sequence


class ThresholdTuner:
    """Chooses and evaluates anomaly thresholds from reconstruction errors."""

    # ------------------------------------------------------------------ #
    # Statistics helpers (pure python)
    # ------------------------------------------------------------------ #
    @staticmethod
    def _mean(values: Sequence[float]) -> float:
        """Arithmetic mean of ``values`` (``0.0`` for an empty input)."""
        if not values:
            return 0.0
        return math.fsum(values) / float(len(values))

    @classmethod
    def _std(cls, values: Sequence[float], mean: float) -> float:
        """Population standard deviation about ``mean``.

        Returns ``0.0`` for inputs with fewer than two elements (no spread is
        defined). Uses the population (``N``) denominator to match the way the
        model baseline statistics are computed elsewhere.
        """
        n = len(values)
        if n < 2:
            return 0.0
        variance = math.fsum((float(v) - mean) ** 2 for v in values) / float(n)
        return math.sqrt(variance)

    @staticmethod
    def _quantile(sorted_values: List[float], q: float) -> float:
        """Linear-interpolation quantile of an already-sorted list.

        Args:
            sorted_values: Ascending-sorted values (must be non-empty).
            q: Quantile in ``[0, 1]``.

        Returns:
            The interpolated quantile value, matching the common
            ``numpy.quantile`` "linear" convention.
        """
        if not sorted_values:
            return 0.0
        if len(sorted_values) == 1:
            return float(sorted_values[0])

        q = min(1.0, max(0.0, q))
        position = q * (len(sorted_values) - 1)
        lower_index = int(math.floor(position))
        upper_index = int(math.ceil(position))
        if lower_index == upper_index:
            return float(sorted_values[lower_index])

        fraction = position - lower_index
        lower = float(sorted_values[lower_index])
        upper = float(sorted_values[upper_index])
        return lower + (upper - lower) * fraction

    # ------------------------------------------------------------------ #
    # Tuning
    # ------------------------------------------------------------------ #
    def tune_from_errors(
        self,
        errors: Sequence[float],
        n_std: float = 2.0,
        target_fpr: float = 0.05,
    ) -> float:
        """Pick a threshold from a sample of normal reconstruction errors.

        The result is ``max(mean + n_std * std, quantile_{1 - target_fpr})`` so
        the chosen cutoff respects both a parametric and an empirical bound on the
        normal false-positive rate.

        Args:
            errors: Reconstruction errors observed on *normal* data.
            n_std: Number of standard deviations above the mean for the
                parametric cutoff.
            target_fpr: Target false-positive rate; the ``(1 - target_fpr)``
                empirical quantile forms the lower bound on the threshold.

        Returns:
            The selected threshold. Edge cases: an empty input returns ``0.0``;
            a single-element input returns that element (scaled by ``n_std`` has
            no spread to add, so the lone value itself is used).
        """
        cleaned = [float(e) for e in errors]
        if not cleaned:
            return 0.0
        if len(cleaned) == 1:
            return float(cleaned[0])

        mean = self._mean(cleaned)
        std = self._std(cleaned, mean)
        base_threshold = mean + float(n_std) * std

        ordered = sorted(cleaned)
        quantile_level = 1.0 - float(target_fpr)
        quantile_threshold = self._quantile(ordered, quantile_level)

        return max(base_threshold, quantile_threshold)

    def tune(
        self,
        model: Any,
        validation_features: Sequence[Any],
        n_std: float = 2.0,
        target_fpr: float = 0.05,
    ) -> float:
        """Compute per-sample errors from a model, then tune a threshold.

        Each row of ``validation_features`` is passed to
        ``model.reconstruction_error`` and the (scalar) result is coerced to a
        python ``float``. The collected errors are then handed to
        :meth:`tune_from_errors`.

        This is the only method that interacts with a torch model, and it does so
        purely through duck typing at call time — no torch import happens here.

        Args:
            model: An object exposing ``reconstruction_error(row) -> scalar``
                (e.g. a :class:`~behaveguard.models.autoencoder.BehaviorAutoencoder`).
            validation_features: Iterable of feature rows drawn from normal data.
            n_std: Forwarded to :meth:`tune_from_errors`.
            target_fpr: Forwarded to :meth:`tune_from_errors`.

        Returns:
            The tuned threshold from :meth:`tune_from_errors`.
        """
        errors: List[float] = []
        for row in validation_features:
            errors.append(float(model.reconstruction_error(row)))
        return self.tune_from_errors(errors, n_std=n_std, target_fpr=target_fpr)

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        normal_errors: Sequence[float],
        attack_errors: Sequence[float],
        threshold: float,
    ) -> Dict[str, float]:
        """Score a threshold against labelled normal/attack error samples.

        Computes the rates and a threshold-independent ROC-AUC via the
        Mann-Whitney U statistic (ties contribute ``0.5``), which equals the
        probability that a randomly chosen attack error exceeds a randomly chosen
        normal error.

        Args:
            normal_errors: Reconstruction errors from normal (negative) samples.
            attack_errors: Reconstruction errors from attack (positive) samples.
            threshold: The cutoff at/above which a sample is flagged anomalous.

        Returns:
            A dict with ``true_positive_rate``, ``false_positive_rate``,
            ``f1_score``, ``roc_auc`` and the echoed ``threshold``.
        """
        thr = float(threshold)
        normals = [float(e) for e in normal_errors]
        attacks = [float(e) for e in attack_errors]

        n_pos = len(attacks)
        n_neg = len(normals)

        true_positives = sum(1 for e in attacks if e >= thr)
        false_positives = sum(1 for e in normals if e >= thr)

        tpr = (true_positives / n_pos) if n_pos > 0 else 0.0
        fpr = (false_positives / n_neg) if n_neg > 0 else 0.0

        precision_denom = true_positives + false_positives
        precision = (true_positives / precision_denom) if precision_denom > 0 else 0.0
        recall = tpr  # recall is identical to the true-positive rate
        f1_denom = precision + recall
        f1_score = (2.0 * precision * recall / f1_denom) if f1_denom > 0 else 0.0

        roc_auc = self._roc_auc(normals, attacks)

        return {
            "true_positive_rate": tpr,
            "false_positive_rate": fpr,
            "f1_score": f1_score,
            "roc_auc": roc_auc,
            "threshold": thr,
        }

    @staticmethod
    def _roc_auc(normals: Sequence[float], attacks: Sequence[float]) -> float:
        """ROC-AUC from the Mann-Whitney U statistic with mid-rank tie handling.

        ``AUC = U / (n_pos * n_neg)`` where ``U`` counts, over every
        attack/normal pair, ``1`` when the attack error is strictly larger and
        ``0.5`` on a tie. Returns ``0.0`` when either class is empty (AUC is
        undefined there).
        """
        n_pos = len(attacks)
        n_neg = len(normals)
        if n_pos == 0 or n_neg == 0:
            return 0.0

        # Rank-based computation for O((n+m) log(n+m)) instead of O(n*m).
        labelled = [(float(v), 1) for v in attacks] + [(float(v), 0) for v in normals]
        labelled.sort(key=lambda pair: pair[0])

        # Assign mid-ranks (1-based), averaging ranks across tied values.
        ranks: List[float] = [0.0] * len(labelled)
        i = 0
        total = len(labelled)
        while i < total:
            j = i
            while j + 1 < total and labelled[j + 1][0] == labelled[i][0]:
                j += 1
            # Ranks i..j (0-based) -> average of (i+1)..(j+1) in 1-based ranks.
            average_rank = (i + 1 + j + 1) / 2.0
            for k in range(i, j + 1):
                ranks[k] = average_rank
            i = j + 1

        # Sum of ranks of the positive (attack) class.
        rank_sum_pos = math.fsum(
            ranks[idx] for idx, (_value, label) in enumerate(labelled) if label == 1
        )
        u_pos = rank_sum_pos - (n_pos * (n_pos + 1)) / 2.0
        return u_pos / float(n_pos * n_neg)
