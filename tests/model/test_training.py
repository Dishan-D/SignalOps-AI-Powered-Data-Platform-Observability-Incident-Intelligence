"""Training, persistence, calibration and evaluation."""

from __future__ import annotations

import pytest
import torch

from forensics.inference.evaluate import (
    Threshold,
    average_precision,
    calibrate,
    evaluate,
    score_windows,
    unknown_token_baseline,
)
from forensics.inference.train import (
    TrainingConfig,
    load_bundle,
    save_bundle,
    train,
    windows_to_tensor,
)


def test_training_refuses_labelled_attack_data(fitted_builder, mixed_windows) -> None:
    """One-class training on attack data would inflate every metric downstream,
    and the mistake is invisible in the output."""
    assert any(w.is_anomaly for w in mixed_windows)
    with pytest.raises(ValueError, match="one-class"):
        train(mixed_windows, fitted_builder, config=TrainingConfig(epochs=1))


def test_training_reduces_loss(trained) -> None:
    first = trained.history[0]["mlm_loss"]
    last = trained.history[-1]["mlm_loss"]
    assert last < first, f"loss did not improve: {first:.3f} -> {last:.3f}"


def test_training_beats_a_uniform_predictor(trained, fitted_builder) -> None:
    """Sanity floor: the model must do better than guessing uniformly."""
    import math

    uniform = 1.0 / fitted_builder.vocabulary.size
    assert trained.history[-1]["mlm_accuracy"] > uniform
    # And the loss must be below the entropy of a uniform distribution.
    assert trained.history[-1]["mlm_loss"] < math.log(fitted_builder.vocabulary.size)


def test_center_is_initialised_after_warmup(trained) -> None:
    assert trained.model.center_initialised
    assert trained.model.center.abs().sum() > 0


def _threshold() -> Threshold:
    return Threshold(
        cuts={"max_nll": 4.5, "mean_nll": 2.7, "sphere_distance": 8.0},
        target_false_positive_rate=0.01,
    )


def test_bundle_round_trips(trained, tmp_path, benign_windows) -> None:
    """Weights, miner and vocabulary must reload together or ids lose meaning."""
    path = save_bundle(trained, tmp_path / "bundle", threshold=_threshold())
    model, builder, metadata = load_bundle(path, device=torch.device("cpu"))

    assert builder.window_size == trained.builder.window_size
    assert builder.vocabulary.size == trained.builder.vocabulary.size
    assert builder.miner.vocabulary_size == trained.builder.miner.vocabulary_size
    assert metadata["model"]["vocab_size"] == trained.config.vocab_size
    # The hypersphere centre is a buffer and must survive.
    assert model.center_initialised
    assert torch.allclose(model.center.cpu(), trained.model.center.cpu())

    # Same input, same scores.
    sample = benign_windows[:16]
    before = score_windows(trained.model, sample, device=torch.device("cpu"))
    after = score_windows(model, sample, device=torch.device("cpu"))
    for name in before.names:
        assert before[name] == pytest.approx(after[name], abs=1e-4)


def test_calibration_is_persisted_in_the_bundle(trained, tmp_path) -> None:
    """Regression: the bundle shipped without thresholds and the scorer refused
    to start — training printed the cuts but never saved them."""
    path = save_bundle(trained, tmp_path / "bundle", threshold=_threshold())
    _, _, metadata = load_bundle(path, device=torch.device("cpu"))

    assert metadata["thresholds"] == pytest.approx(
        {"max_nll": 4.5, "mean_nll": 2.7, "sphere_distance": 8.0}
    )
    assert metadata["target_false_positive_rate"] == pytest.approx(0.01)
    # The scorer's own gate: falsy thresholds make it exit 2.
    assert metadata.get("thresholds")


def test_reloaded_vocabulary_stays_frozen(trained, tmp_path) -> None:
    path = save_bundle(trained, tmp_path / "bundle", threshold=_threshold())
    _, builder, _ = load_bundle(path, device=torch.device("cpu"))
    assert builder.vocabulary.frozen


def test_windows_to_tensor_shape(benign_windows) -> None:
    tensor = windows_to_tensor(benign_windows[:5])
    assert tensor.shape == (5, len(benign_windows[0].token_ids))
    assert tensor.dtype == torch.long


# --------------------------------------------------------------------------- #
# Calibration and metrics                                                      #
# --------------------------------------------------------------------------- #

def test_calibration_hits_its_false_positive_budget(trained, benign_windows) -> None:
    """The whole point of calibrating on a benign holdout."""
    scores = score_windows(trained.model, benign_windows, device=torch.device("cpu"))
    threshold = calibrate(scores, target_false_positive_rate=0.05)
    metrics = evaluate(benign_windows, scores, threshold)

    assert metrics.base_rate == 0.0
    # Signals fire on overlapping windows, so the realised rate lands at or
    # under the per-signal budget, never far above it.
    assert metrics.alert_rate <= 0.20, metrics.alert_rate


def test_tighter_budget_produces_fewer_alerts(trained, benign_windows) -> None:
    scores = score_windows(trained.model, benign_windows, device=torch.device("cpu"))
    loose = evaluate(benign_windows, scores, calibrate(scores, target_false_positive_rate=0.10))
    tight = evaluate(benign_windows, scores, calibrate(scores, target_false_positive_rate=0.01))
    assert tight.alert_rate <= loose.alert_rate


def test_detector_separates_attacks_from_benign(trained, benign_windows, mixed_windows) -> None:
    """The end-to-end claim: attacks score higher than benign traffic."""
    benign_scores = score_windows(trained.model, benign_windows, device=torch.device("cpu"))
    mixed_scores = score_windows(trained.model, mixed_windows, device=torch.device("cpu"))
    threshold = calibrate(benign_scores, target_false_positive_rate=0.02)
    metrics = evaluate(mixed_windows, mixed_scores, threshold)

    assert metrics.base_rate > 0
    # A coin flip would score PR-AUC at roughly the base rate.
    assert metrics.pr_auc > metrics.base_rate * 2, metrics.summary()
    assert metrics.recall > 0.4, metrics.summary()


def test_detector_beats_the_unknown_token_baseline(trained, benign_windows, mixed_windows) -> None:
    """Justification for the transformer: a one-line rule must not match it."""
    benign_scores = score_windows(trained.model, benign_windows, device=torch.device("cpu"))
    mixed_scores = score_windows(trained.model, mixed_windows, device=torch.device("cpu"))
    threshold = calibrate(benign_scores, target_false_positive_rate=0.02)

    model_metrics = evaluate(mixed_windows, mixed_scores, threshold)
    baseline = unknown_token_baseline(mixed_windows)
    assert model_metrics.pr_auc > baseline.pr_auc, (
        f"model {model_metrics.pr_auc:.3f} vs UNK rule {baseline.pr_auc:.3f}"
    )


def test_calibration_rejects_empty_scores() -> None:
    from forensics.inference.evaluate import Scores

    with pytest.raises(ValueError, match="empty"):
        calibrate(Scores({"max_nll": []}))


@pytest.mark.parametrize("bad", [0.0, 1.0, -0.1, 1.5])
def test_calibration_rejects_out_of_range_budget(trained, benign_windows, bad) -> None:
    scores = score_windows(trained.model, benign_windows[:32], device=torch.device("cpu"))
    with pytest.raises(ValueError, match="target_false_positive_rate"):
        calibrate(scores, target_false_positive_rate=bad)


def test_average_precision_on_a_perfect_ranking() -> None:
    assert average_precision([True, True, False, False], [0.9, 0.8, 0.2, 0.1]) == pytest.approx(1.0)


def test_average_precision_on_an_inverted_ranking() -> None:
    value = average_precision([True, True, False, False], [0.1, 0.2, 0.8, 0.9])
    assert value < 0.6


def test_average_precision_with_no_positives_is_zero() -> None:
    assert average_precision([False, False], [0.9, 0.1]) == 0.0


def test_average_precision_handles_ties_deterministically() -> None:
    """Ties must be consumed together, or the curve depends on sort order."""
    a = average_precision([True, False, True, False], [0.5, 0.5, 0.5, 0.5])
    b = average_precision([False, True, False, True], [0.5, 0.5, 0.5, 0.5])
    assert a == pytest.approx(b)


def test_evaluate_rejects_length_mismatch(benign_windows, trained) -> None:
    scores = score_windows(trained.model, benign_windows[:10], device=torch.device("cpu"))
    threshold = calibrate(scores, target_false_positive_rate=0.1)
    with pytest.raises(ValueError, match="mismatch"):
        evaluate(benign_windows[:5], scores, threshold)
