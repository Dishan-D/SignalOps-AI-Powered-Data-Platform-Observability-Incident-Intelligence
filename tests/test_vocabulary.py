"""Log-key vocabulary invariants."""

from __future__ import annotations

from forensics.inference.vocabulary import (
    PAD_ID,
    UNK_ID,
    LogKey,
    LogKeyVocabulary,
)


def test_pad_is_zero_so_zero_tensors_are_valid_padding() -> None:
    assert PAD_ID == 0


def test_same_key_returns_the_same_id() -> None:
    vocab = LogKeyVocabulary()
    assert vocab.add(LogKey(1, "failure")) == vocab.add(LogKey(1, "failure"))


def test_outcome_is_part_of_the_key() -> None:
    """Drain merges Failed/Accepted password; the outcome restores the split."""
    vocab = LogKeyVocabulary()
    assert vocab.add(LogKey(4, "failure")) != vocab.add(LogKey(4, "success"))


def test_ids_avoid_the_reserved_range() -> None:
    vocab = LogKeyVocabulary()
    assert vocab.add(LogKey(1, "success")) > max(PAD_ID, UNK_ID)


def test_frozen_vocabulary_returns_unk_instead_of_growing() -> None:
    vocab = LogKeyVocabulary()
    vocab.add(LogKey(1, "success"))
    size = vocab.size
    vocab.freeze()

    assert vocab.add(LogKey(99, "failure")) == UNK_ID
    assert vocab.size == size


def test_lookup_never_mutates() -> None:
    vocab = LogKeyVocabulary()
    size = vocab.size
    assert vocab.lookup(LogKey(7, "success")) == UNK_ID
    assert vocab.size == size


def test_round_trip_preserves_ids_and_frozen_state() -> None:
    vocab = LogKeyVocabulary()
    keys = [LogKey(i, o) for i in range(5) for o in ("success", "failure")]
    ids = [vocab.add(k) for k in keys]
    vocab.freeze()

    restored = LogKeyVocabulary.from_dict(vocab.to_dict())
    assert restored.frozen
    assert restored.size == vocab.size
    assert [restored.lookup(k) for k in keys] == ids
