"""Lexical (BM25) retrieval over Markdown runbooks, section by section.

Six runbooks do not justify embeddings or a vector store: the vocabulary is
narrow and technical (error codes, table names, component names) and exact term
overlap is what matters. Each ``##``/``###`` section is indexed as its own
document so a hit cites *where* in a runbook the guidance is, and every hit
carries its source path and section title.

Runbook text is treated as untrusted content by its consumers (the agent wraps
it as data); this module only retrieves it.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import BaseModel

MAX_DOC_BYTES = 200_000
MAX_QUERY_CHARS = 500
EXCERPT_CHARS = 700

_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.]*[a-z0-9]|[a-z0-9]")
_HEADING = re.compile(r"^(#{1,3})\s+(.+?)\s*#*\s*$")
_STOPWORDS = frozenset(
    ["a", "an", "and", "are", "as", "at", "be", "by", "can", "do", "does", "for", "from", "has", "have", "how", "if", "in", "into", "is", "it", "its", "not", "of", "on", "or", "our", "so", "that", "the", "their", "them", "then", "there", "these", "this", "to", "was", "were", "what", "when", "where", "which", "while", "who", "why", "will", "with", "you", "your"]
)


def _stem(token: str) -> str:
    for suffix in ("ing", "ies", "es", "ed", "s"):
        if len(token) > len(suffix) + 3 and token.endswith(suffix):
            return token[: -len(suffix)] + ("y" if suffix == "ies" else "")
    return token


def tokenize(text: str) -> list[str]:
    """Lowercase terms; compound tokens (``unknown_category``, ``logs.raw.dlq``)
    are kept whole *and* split, so either form matches."""
    out: list[str] = []
    for raw in _TOKEN.findall(text.lower()):
        if raw in _STOPWORDS:
            continue
        out.append(_stem(raw))
        if "_" in raw or "." in raw:
            out.extend(_stem(p) for p in re.split(r"[_.]", raw)
                       if p and p not in _STOPWORDS and len(p) > 1)
    return out


class RunbookHit(BaseModel):
    source: str
    title: str
    section: str
    score: float
    excerpt: str
    matched_terms: list[str]


@dataclass
class _Section:
    source: str
    title: str
    section: str
    text: str
    terms: Counter[str] = field(default_factory=Counter)
    length: int = 0


@dataclass
class RunbookIndex:
    directory: Path
    sections: list[_Section] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    _df: Counter[str] = field(default_factory=Counter)
    _avg_len: float = 0.0

    @classmethod
    def load(cls, directory: Path) -> RunbookIndex:
        index = cls(directory=directory)
        if not directory.is_dir():
            index.errors.append(f"runbook directory not found: {directory}")
            return index
        for path in sorted(directory.glob("*.md")):
            index._add_file(path)
        if index.sections:
            index._avg_len = sum(s.length for s in index.sections) / len(index.sections)
            for s in index.sections:
                index._df.update(set(s.terms))
        return index

    @property
    def available(self) -> bool:
        return bool(self.sections)

    @property
    def documents(self) -> list[str]:
        return sorted({s.source for s in self.sections})

    def _add_file(self, path: Path) -> None:
        source = f"{self.directory.name}/{path.name}"
        try:
            if path.stat().st_size > MAX_DOC_BYTES:
                self.errors.append(f"{source}: larger than {MAX_DOC_BYTES} bytes, skipped")
                return
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            self.errors.append(f"{source}: unreadable ({exc.__class__.__name__}), skipped")
            return
        if not text.strip():
            self.errors.append(f"{source}: empty, skipped")
            return

        title = path.stem.replace("-", " ").title()
        current = "Overview"
        buffer: list[str] = []
        parsed: list[tuple[str, str]] = []
        for line in text.splitlines():
            match = _HEADING.match(line)
            if match and len(match.group(1)) == 1:
                title = match.group(2)
                continue
            if match:
                if "\n".join(buffer).strip():
                    parsed.append((current, "\n".join(buffer).strip()))
                current, buffer = match.group(2), []
                continue
            buffer.append(line)
        if "\n".join(buffer).strip():
            parsed.append((current, "\n".join(buffer).strip()))
        if not parsed:
            self.errors.append(f"{source}: no content sections, skipped")
            return

        for section, body in parsed:
            # Headings count double: a match on "Symptoms" or a title term is
            # a stronger signal than one buried in a paragraph.
            terms = Counter(tokenize(body) + tokenize(section) * 2 + tokenize(title) * 2)
            self.sections.append(_Section(source=source, title=title, section=section,
                                          text=body, terms=terms, length=sum(terms.values())))

    def search(self, query: str, *, limit: int = 3, k1: float = 1.5, b: float = 0.75) -> list[RunbookHit]:
        if not query or not query.strip():
            raise ValueError("query must not be empty")
        if len(query) > MAX_QUERY_CHARS:
            raise ValueError(f"query must be at most {MAX_QUERY_CHARS} characters")
        limit = max(1, min(limit, 10))
        q_terms = list(dict.fromkeys(tokenize(query)))
        if not q_terms or not self.sections:
            return []
        n = len(self.sections)
        scored: list[tuple[float, _Section, list[str]]] = []
        for section in self.sections:
            score = 0.0
            matched = []
            for term in q_terms:
                tf = section.terms.get(term, 0)
                if not tf:
                    continue
                df = self._df[term]
                idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
                norm = tf * (k1 + 1) / (tf + k1 * (1 - b + b * section.length / (self._avg_len or 1)))
                score += idf * norm
                matched.append(term)
            if score > 0:
                scored.append((score, section, matched))
        scored.sort(key=lambda item: (-item[0], item[1].source, item[1].section))
        return [
            RunbookHit(
                source=s.source, title=s.title, section=s.section, score=round(score, 3),
                excerpt=s.text if len(s.text) <= EXCERPT_CHARS else s.text[:EXCERPT_CHARS] + "…",
                matched_terms=matched,
            )
            for score, s, matched in scored[:limit]
        ]

    def has_section(self, source: str, section: str) -> bool:
        return any(s.source == source and s.section == section for s in self.sections)
