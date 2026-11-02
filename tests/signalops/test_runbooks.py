"""Runbook retrieval: relevance, attribution, empty/missing/malformed inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from signalops.retrieval.runbooks import RunbookIndex, tokenize


def test_all_six_runbooks_load(runbooks: RunbookIndex) -> None:
    assert runbooks.errors == []
    assert runbooks.documents == sorted(f"runbooks/{n}.md" for n in (
        "anomaly-investigation", "dead-letter-queue-investigation", "evidence-ledger-verification",
        "kafka-ingestion-failures", "schema-validation-errors", "spark-processing-delays"))


def test_every_runbook_has_the_required_sections(runbooks: RunbookIndex) -> None:
    required = {"Purpose", "Symptoms", "Evidence to collect", "Diagnostic steps", "Expected observations",
                "Possible causes", "Recommended next steps", "Escalation criteria", "Limitations and safety"}
    for doc in runbooks.documents:
        sections = {s.section for s in runbooks.sections if s.source == doc}
        assert required <= sections, f"{doc} missing {required - sections}"


@pytest.mark.parametrize(("query", "expected_source"), [
    ("records rejected unknown_category severity_out_of_range", "runbooks/schema-validation-errors.md"),
    ("spark query terminated exception checkpoint", "runbooks/spark-processing-delays.md"),
    ("event_modified merkle root mismatch", "runbooks/evidence-ledger-verification.md"),
    ("broker unreachable missing topics", "runbooks/kafka-ingestion-failures.md"),
    ("reverse shell brute force host detection", "runbooks/anomaly-investigation.md"),
    ("replay dead-lettered records producer spool", "runbooks/dead-letter-queue-investigation.md"),
])
def test_relevant_document_ranked_first(runbooks: RunbookIndex, query: str, expected_source: str) -> None:
    hits = runbooks.search(query)
    assert hits and hits[0].source == expected_source


def test_hits_carry_source_section_and_excerpt(runbooks: RunbookIndex) -> None:
    hit = runbooks.search("unparseable_timestamp")[0]
    assert hit.source == "runbooks/schema-validation-errors.md"
    assert hit.section == "Error code reference"
    assert hit.title == "Schema Validation Errors"
    assert "unparseable_timestamp" in hit.excerpt and "unparseable_timestamp" in hit.matched_terms
    assert runbooks.has_section(hit.source, hit.section)


def test_no_result_returns_empty(runbooks: RunbookIndex) -> None:
    assert runbooks.search("xylophone quasar") == []


@pytest.mark.parametrize("query", ["", "   ", "x" * 501])
def test_invalid_queries_rejected(runbooks: RunbookIndex, query: str) -> None:
    with pytest.raises(ValueError):
        runbooks.search(query)


def test_stopword_only_query_returns_empty(runbooks: RunbookIndex) -> None:
    assert runbooks.search("the and of") == []


def test_missing_directory(tmp_path: Path) -> None:
    index = RunbookIndex.load(tmp_path / "nope")
    assert not index.available and "not found" in index.errors[0]
    assert index.search("anything") == []


def test_malformed_documents_are_skipped_with_errors(tmp_path: Path) -> None:
    (tmp_path / "empty.md").write_text("", encoding="utf-8")
    (tmp_path / "binary.md").write_bytes(b"\xff\xfe\x00\x81garbage")
    (tmp_path / "headings-only.md").write_text("# Title\n## A\n## B\n", encoding="utf-8")
    (tmp_path / "no-h1.md").write_text("Some text about kafka brokers.\n## Steps\nRestart kafka.\n",
                                       encoding="utf-8")
    index = RunbookIndex.load(tmp_path)
    assert len(index.errors) == 3
    hit = index.search("kafka")[0]
    assert hit.title == "No H1"  # falls back to the filename
    assert hit.source == f"{tmp_path.name}/no-h1.md"


def test_tokenizer_keeps_compound_terms_whole_and_split() -> None:
    terms = tokenize("logs.raw.dlq unknown_category")
    assert "logs.raw.dlq" in terms and "dlq" in terms
    assert "unknown_category" in terms and "category" in terms
