"""Model mechanics: masking, shapes, padding, and the scoring signals."""

from __future__ import annotations

import torch

from forensics.inference.model import (
    LogBERT,
    ModelConfig,
    count_parameters,
    mask_tokens,
)
from forensics.inference.vocabulary import FIRST_FREE_ID, MASK_ID, PAD_ID


def _model(vocab: int = 12, length: int = 8) -> LogBERT:
    torch.manual_seed(0)
    return LogBERT(ModelConfig(vocab_size=vocab, max_sequence_length=length, d_model=32,
                               n_heads=4, n_layers=2, d_feedforward=64))


def test_forward_shapes() -> None:
    model = _model()
    tokens = torch.randint(FIRST_FREE_ID, 12, (4, 8))
    logits, pooled = model(tokens)
    assert logits.shape == (4, 8, 12)
    assert pooled.shape == (4, 32)


def test_d_model_must_divide_by_heads() -> None:
    import pytest

    with pytest.raises(ValueError, match="divisible"):
        ModelConfig(vocab_size=10, d_model=30, n_heads=4)


def test_padding_does_not_change_the_pooled_representation() -> None:
    """Otherwise a short host's score depends on how much padding it got."""
    model = _model().eval()
    real = torch.tensor([[3, 4, 5, 6]])
    padded = torch.tensor([[3, 4, 5, 6, PAD_ID, PAD_ID, PAD_ID, PAD_ID]])

    with torch.no_grad():
        _, pooled_real = model(real)
        _, pooled_padded = model(padded)
    assert torch.allclose(pooled_real, pooled_padded, atol=1e-5)


def test_mask_tokens_never_selects_padding() -> None:
    tokens = torch.tensor([[3, 4, PAD_ID, PAD_ID]] * 32)
    _, labels = mask_tokens(tokens, mask_probability=0.9, vocab_size=12)
    assert (labels[:, 2:] == -100).all()


def test_mask_tokens_marks_unselected_as_ignored() -> None:
    tokens = torch.randint(FIRST_FREE_ID, 12, (16, 8))
    corrupted, labels = mask_tokens(tokens, mask_probability=0.3, vocab_size=12)
    selected = labels != -100
    assert selected.any()
    # Where a label exists it must equal the original token.
    assert (labels[selected] == tokens[selected]).all()
    # Unselected positions are untouched.
    assert (corrupted[~selected] == tokens[~selected]).all()


def test_mask_tokens_uses_the_mask_id() -> None:
    tokens = torch.randint(FIRST_FREE_ID, 12, (64, 8))
    corrupted, labels = mask_tokens(tokens, mask_probability=0.9, vocab_size=12)
    assert (corrupted == MASK_ID).any()


def test_mask_tokens_never_emits_reserved_ids_as_random_replacements() -> None:
    """Random replacements must be real log keys, not PAD/UNK/MASK."""
    tokens = torch.full((256, 8), FIRST_FREE_ID + 1)
    corrupted, _ = mask_tokens(tokens, mask_probability=1.0, vocab_size=12)
    replaced = corrupted[(corrupted != MASK_ID) & (corrupted != FIRST_FREE_ID + 1)]
    if replaced.numel():
        assert (replaced >= FIRST_FREE_ID).all()


def test_mask_tokens_always_selects_something() -> None:
    """A batch with nothing selected yields a NaN loss."""
    tokens = torch.randint(FIRST_FREE_ID, 12, (8, 8))
    _, labels = mask_tokens(tokens, mask_probability=0.0, vocab_size=12)
    assert (labels != -100).any()


def test_center_initialisation_avoids_zero_coordinates() -> None:
    """A zero coordinate lets the encoder satisfy the objective by collapsing."""
    model = _model()
    pooled = torch.zeros(16, 32)
    model.initialise_center(pooled)
    assert (model.center.abs() >= 0.01 - 1e-9).all()
    assert model.center_initialised


def test_position_surprise_reports_per_position_nll() -> None:
    model = _model().eval()
    tokens = torch.tensor([[3, 4, 5, 6, 7, 8, 9, PAD_ID]])
    result = model.position_surprise(tokens, top_g=3)

    assert result["nll"].shape == tokens.shape
    assert (result["nll"] >= 0).all()
    # Padding contributes nothing and is not a valid position.
    assert result["nll"][0, -1] == 0
    assert not result["valid"][0, -1]


def test_anomaly_scores_expose_all_signals() -> None:
    model = _model().eval()
    tokens = torch.randint(FIRST_FREE_ID, 12, (5, 8))
    scores = model.anomaly_scores(tokens, top_g=3)
    for key in ("max_nll", "mean_nll", "miss_ratio", "sphere_distance"):
        assert scores[key].shape == (5,)
    assert (scores["miss_ratio"] >= 0).all() and (scores["miss_ratio"] <= 1).all()


def test_max_nll_exceeds_mean_nll() -> None:
    """max is the signal that survives dilution by a long benign window."""
    model = _model().eval()
    tokens = torch.randint(FIRST_FREE_ID, 12, (8, 8))
    scores = model.anomaly_scores(tokens)
    assert (scores["max_nll"] >= scores["mean_nll"] - 1e-5).all()


def test_model_is_small_enough_not_to_memorise() -> None:
    assert count_parameters(_model()) < 500_000
