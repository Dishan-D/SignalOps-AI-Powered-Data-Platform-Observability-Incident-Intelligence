"""Detection scoring, threshold calibration and evaluation.

**Accuracy is not reported anywhere here, on purpose.** At a realistic base rate
a detector that flags nothing scores 99%+ accuracy and is worthless. The metrics
that matter for a security detector are precision (what fraction of alerts waste
an analyst's time), recall (what fraction of attacks are missed), and PR-AUC,
which unlike ROC-AUC does not flatter a model on heavily imbalanced data.

Thresholds are calibrated on a benign-only holdout by picking the quantile that
yields a target false-positive rate. That is how this is done in practice: an
operations team can state the alert budget it can absorb, but nobody can state
in advance what miss ratio counts as "high".
"""

from __future__ import annotations

from dataclasses import dataclass, field

import torch

from forensics.inference.model import LogBERT
from forensics.inference.sequences import SequenceWindow
from forensics.inference.train import windows_to_tensor

#: Signals used for the alert decision. ``miss_ratio`` is computed and reported
#: for comparison with the published LogBERT rule but is deliberately not a
#: decision signal here — see :meth:`LogBERT.anomaly_scores`.
DECISION_SIGNALS = ("max_nll", "mean_nll", "sphere_distance")


@dataclass(frozen=True, slots=True)
class Scores:
    """Raw per-window model output, one list per signal."""

    signals: dict[str, list[float]]

    def __len__(self) -> int:
        return len(next(iter(self.signals.values()))) if self.signals else 0

    def __getitem__(self, name: str) -> list[float]:
        return self.signals[name]

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self.signals)


@dataclass(frozen=True, slots=True)
class Threshold:
    """A calibrated decision boundary, one cut per decision signal."""

    cuts: dict[str, float]
    target_false_positive_rate: float

    def flags(self, values: dict[str, float]) -> bool:
        """Alert if *any* decision signal exceeds its cut.

        OR rather than AND: the signals catch different things — ``max_nll`` a
        single impossible event, ``mean_nll`` a sustained burst,
        ``sphere_distance`` a globally unusual session — and requiring agreement
        would discard whichever one actually saw the attack.
        """
        return any(values[name] >= cut for name, cut in self.cuts.items())

    def normalised(self, values: dict[str, float]) -> float:
        """Largest signal expressed as a multiple of its own cut.

        Gives a single rankable score consistent with the OR decision rule, so
        PR-AUC measures the rule actually in use rather than one signal alone.
        """
        return max(
            (values[name] / cut if cut > 0 else 0.0) for name, cut in self.cuts.items()
        )


@dataclass(frozen=True, slots=True)
class Metrics:
    """Evaluation at one operating point."""

    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    pr_auc: float
    base_rate: float
    alert_rate: float
    per_scenario_recall: dict[str, float] = field(default_factory=dict)

    def summary(self) -> str:
        return (
            f"precision={self.precision:.3f} recall={self.recall:.3f} "
            f"f1={self.f1:.3f} pr_auc={self.pr_auc:.3f} "
            f"(base_rate={self.base_rate:.2%}, alert_rate={self.alert_rate:.2%})"
        )


@torch.no_grad()
def score_windows(
    model: LogBERT,
    windows: list[SequenceWindow],
    *,
    device: torch.device | None = None,
    top_g: int = 3,
    batch_size: int = 256,
) -> Scores:
    """Score windows in batches."""
    if not windows:
        return Scores({name: [] for name in (*DECISION_SIGNALS, "miss_ratio")})

    model.eval()
    resolved_device = device or next(model.parameters()).device
    tensor = windows_to_tensor(windows)

    collected: dict[str, list[float]] = {}
    # Chunked: position_surprise expands each batch to B*L sequences, so a large
    # batch multiplies into a very large forward pass.
    for start in range(0, tensor.size(0), batch_size):
        batch = tensor[start : start + batch_size].to(resolved_device)
        scores = model.anomaly_scores(batch, top_g=top_g)
        for name, values in scores.items():
            if name == "valid_positions":
                continue
            collected.setdefault(name, []).extend(values.cpu().tolist())

    return Scores(collected)


def calibrate(
    benign_scores: Scores,
    *,
    target_false_positive_rate: float = 0.01,
    signals: tuple[str, ...] = DECISION_SIGNALS,
) -> Threshold:
    """Choose per-signal cuts from benign-only scores.

    Each signal gets the *full* budget rather than a share of it: they fire on
    overlapping windows, so splitting it would over-tighten every cut and the
    realised rate would land well under target. The rate actually achieved is
    measured by :func:`evaluate`, never assumed.
    """
    if not len(benign_scores):
        raise ValueError("cannot calibrate on an empty score set")
    if not 0.0 < target_false_positive_rate < 1.0:
        raise ValueError("target_false_positive_rate must be in (0, 1)")

    quantile = 1.0 - target_false_positive_rate
    return Threshold(
        cuts={
            name: _quantile(benign_scores[name], quantile)
            for name in signals
            if name in benign_scores.signals
        },
        target_false_positive_rate=target_false_positive_rate,
    )


def evaluate(
    windows: list[SequenceWindow], scores: Scores, threshold: Threshold
) -> Metrics:
    """Confusion matrix and derived metrics at ``threshold``."""
    if len(windows) != len(scores):
        raise ValueError(
            f"window/score length mismatch: {len(windows)} vs {len(scores)}"
        )

    tp = fp = tn = fn = 0
    scenario_totals: dict[str, int] = {}
    scenario_hits: dict[str, int] = {}
    ranked: list[float] = []

    for index, window in enumerate(windows):
        values = {name: scores[name][index] for name in threshold.cuts}
        flagged = threshold.flags(values)
        ranked.append(threshold.normalised(values))
        actual = window.is_anomaly

        if actual and flagged:
            tp += 1
        elif actual:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1

        for scenario in window.scenarios:
            scenario_totals[scenario] = scenario_totals.get(scenario, 0) + 1
            if flagged:
                scenario_hits[scenario] = scenario_hits.get(scenario, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    labels = [w.is_anomaly for w in windows]
    total = len(windows) or 1
    return Metrics(
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        pr_auc=average_precision(labels, ranked),
        base_rate=sum(labels) / total,
        alert_rate=(tp + fp) / total,
        per_scenario_recall={
            name: scenario_hits.get(name, 0) / count
            for name, count in sorted(scenario_totals.items())
        },
    )


def unknown_token_baseline(windows: list[SequenceWindow]) -> Metrics:
    """Control: flag any window containing a log key unseen during training.

    This exists to answer the question a reviewer should ask — *is the
    transformer doing anything a one-line rule could not?* Novel tradecraft
    produces novel templates, so "contains UNK" is a genuinely strong trivial
    detector on synthetic data and the model must beat it to justify itself.

    It also has an obvious real-world failure mode, which is the point: a
    package upgrade that changes a log format produces unseen templates on every
    host at once, and this rule alerts on all of them.
    """
    from forensics.inference.vocabulary import UNK_ID

    tp = fp = tn = fn = 0
    scenario_totals: dict[str, int] = {}
    scenario_hits: dict[str, int] = {}
    ranked: list[float] = []

    for window in windows:
        flagged = UNK_ID in window.token_ids
        ranked.append(1.0 if flagged else 0.0)
        actual = window.is_anomaly
        if actual and flagged:
            tp += 1
        elif actual:
            fn += 1
        elif flagged:
            fp += 1
        else:
            tn += 1
        for scenario in window.scenarios:
            scenario_totals[scenario] = scenario_totals.get(scenario, 0) + 1
            if flagged:
                scenario_hits[scenario] = scenario_hits.get(scenario, 0) + 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    labels = [w.is_anomaly for w in windows]
    total = len(windows) or 1

    return Metrics(
        true_positives=tp, false_positives=fp, true_negatives=tn, false_negatives=fn,
        precision=precision, recall=recall, f1=f1,
        pr_auc=average_precision(labels, ranked),
        base_rate=sum(labels) / total,
        alert_rate=(tp + fp) / total,
        per_scenario_recall={
            name: scenario_hits.get(name, 0) / count
            for name, count in sorted(scenario_totals.items())
        },
    )


def _quantile(values: list[float], q: float) -> float:
    """Linear-interpolated quantile (no numpy dependency in the hot path)."""
    if not values:
        return float("inf")
    ordered = sorted(values)
    if q <= 0:
        return ordered[0]
    if q >= 1:
        return ordered[-1]
    position = q * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def average_precision(labels: list[bool], scores: list[float]) -> float:
    """Area under the precision-recall curve.

    Computed as the step-wise sum used by scikit-learn's ``average_precision``,
    so the number is comparable to what a reader expects, without adding the
    dependency.
    """
    if not labels or not any(labels):
        return 0.0

    ranked = sorted(zip(scores, labels, strict=True), key=lambda p: p[0], reverse=True)
    positives = sum(labels)
    true_positives = 0
    false_positives = 0
    previous_recall = 0.0
    total = 0.0

    index = 0
    while index < len(ranked):
        score = ranked[index][0]
        # Ties must be consumed together, or the curve depends on sort order
        # among equal scores — which is arbitrary.
        while index < len(ranked) and ranked[index][0] == score:
            if ranked[index][1]:
                true_positives += 1
            else:
                false_positives += 1
            index += 1
        precision = true_positives / (true_positives + false_positives)
        recall = true_positives / positives
        total += precision * (recall - previous_recall)
        previous_recall = recall

    return total
