"""Unit tests for the pure-Python scoring layer.

Covers the severity classifier, the human-readable explainer, and the
``ThresholdTuner`` (threshold selection + evaluation). None of these need
numpy/torch, so they run locally and in CI.
"""

from __future__ import annotations

import pytest

from behaveguard.collector.event_types import (
    FileEvent,
    NetworkEvent,
    ProcessEvent,
)
from behaveguard.features.extractor import FeatureExtractor
from behaveguard.models.threshold_tuner import ThresholdTuner
from behaveguard.scoring import Severity, classify, explain, rank_contributions


# --------------------------------------------------------------------------- #
# classify
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "score, expected",
    [
        (95.0, Severity.CRITICAL),
        (90.0, Severity.CRITICAL),  # inclusive critical cutoff
        (75.0, Severity.HIGH),
        (70.0, Severity.HIGH),  # inclusive high cutoff
        (50.0, Severity.MEDIUM),
        (40.0, Severity.MEDIUM),  # inclusive medium floor
        (10.0, Severity.LOW),
        (0.0, Severity.LOW),
    ],
)
def test_classify_mapping(score, expected):
    assert classify(score) is expected


def test_classify_clamps_out_of_range_scores():
    assert classify(1000.0) is Severity.CRITICAL
    assert classify(-50.0) is Severity.LOW


def test_classify_respects_custom_thresholds():
    # With a high cutoff of 50, a 55 score should be HIGH, not MEDIUM.
    assert classify(55.0, high=50.0, critical=80.0, medium=20.0) is Severity.HIGH


# --------------------------------------------------------------------------- #
# explain
# --------------------------------------------------------------------------- #
def _attack_window(base_ns: int = 7_000_000_000_000):
    """Shell exec + sensitive-file read + Tor connection — high-salience signals."""
    return [
        ProcessEvent(
            timestamp_ns=base_ns + 1_000,
            pid=900,
            ppid=1,
            comm="bash",
            exe_path="/bin/bash",
            cmdline="bash -i",
            action="exec",
            exit_code=0,
        ),
        FileEvent(
            timestamp_ns=base_ns + 2_000,
            pid=900,
            comm="cat",
            path="/etc/shadow",
            operation="read",
            flags=0,
            ret=4096,
            bytes_count=4096,
        ),
        NetworkEvent(
            timestamp_ns=base_ns + 3_000,
            pid=900,
            comm="bash",
            src_ip="203.0.113.5",
            dst_ip="198.51.100.9",
            src_port=44000,
            dst_port=9050,  # Tor SOCKS port
            protocol="TCP",
            bytes_count=200,
            direction="outbound",
        ),
    ]


def test_explain_names_the_process_and_calls_out_an_attack_feature():
    extractor = FeatureExtractor(window_seconds=30)
    vector = extractor.extract_vector(_attack_window())

    sentence = explain(vector, FeatureExtractor.FEATURE_NAMES, process_name="bash", top_k=3)

    assert isinstance(sentence, str)
    # The process name must appear.
    assert "bash" in sentence
    # At least one of the high-salience attack callouts must surface. The shell
    # spawn, sensitive-file access, and Tor connection are all candidates.
    lowered = sentence.lower()
    assert any(phrase in lowered for phrase in ("shell", "sensitive system files", "tor")), sentence


def test_explain_falls_back_for_a_benign_all_zero_vector():
    names = FeatureExtractor.FEATURE_NAMES
    zero_vector = [0.0] * FeatureExtractor.NUM_FEATURES
    sentence = explain(zero_vector, names, process_name="nginx")
    assert "nginx" in sentence
    assert "mild deviation" in sentence.lower()


def test_rank_contributions_orders_attack_feature_first():
    extractor = FeatureExtractor(window_seconds=30)
    vector = extractor.extract_vector(_attack_window())
    ranked = rank_contributions(vector, FeatureExtractor.FEATURE_NAMES)

    # Highest-contribution feature should be one of the decisive behavioral
    # signals, not a benign high-frequency syscall.
    top = ranked[0]
    assert top.contribution > 0.0
    assert top.name in {
        "is_shell_spawned",
        "files_in_system_dirs",
        "is_using_tor_port",
    }


# --------------------------------------------------------------------------- #
# ThresholdTuner
# --------------------------------------------------------------------------- #
def test_tune_from_errors_is_positive_for_positive_errors():
    tuner = ThresholdTuner()
    normal_errors = [0.10, 0.12, 0.11, 0.13, 0.10, 0.14, 0.09, 0.12]
    threshold = tuner.tune_from_errors(normal_errors, n_std=2.0, target_fpr=0.05)
    assert threshold > 0.0
    # The threshold should sit at/above the bulk of the normal errors.
    assert threshold >= max(normal_errors) * 0.5


def test_tune_from_errors_edge_cases():
    tuner = ThresholdTuner()
    assert tuner.tune_from_errors([]) == 0.0
    assert tuner.tune_from_errors([0.42]) == pytest.approx(0.42)


def test_evaluate_perfectly_separable_gives_auc_one():
    tuner = ThresholdTuner()
    normal_errors = [0.05, 0.06, 0.04, 0.07, 0.05, 0.06]
    attack_errors = [0.80, 0.90, 0.85, 0.95, 0.88]

    threshold = tuner.tune_from_errors(normal_errors, n_std=2.0, target_fpr=0.05)
    metrics = tuner.evaluate(normal_errors, attack_errors, threshold)

    assert set(metrics) == {
        "true_positive_rate",
        "false_positive_rate",
        "f1_score",
        "roc_auc",
        "threshold",
    }
    # Cleanly separable error distributions -> perfect ranking.
    assert metrics["roc_auc"] == pytest.approx(1.0)
    # The tuned threshold separates the classes perfectly here.
    assert metrics["true_positive_rate"] == pytest.approx(1.0)
    assert metrics["false_positive_rate"] == pytest.approx(0.0)
    assert metrics["f1_score"] == pytest.approx(1.0)
    assert metrics["threshold"] == pytest.approx(threshold)


def test_evaluate_handles_empty_classes():
    tuner = ThresholdTuner()
    metrics = tuner.evaluate([], [], threshold=0.5)
    assert metrics["roc_auc"] == 0.0
    assert metrics["true_positive_rate"] == 0.0
    assert metrics["false_positive_rate"] == 0.0
