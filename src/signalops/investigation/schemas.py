"""Investigation request, report and job models.

The report separates what was *observed* (each claim tied to an evidence item
the agent actually retrieved) from what is *hypothesised* (each tied to
supporting evidence and a qualitative, uncalibrated confidence). Severity is
copied from the deterministic incident policy; the model never sets it.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from signalops.models import IncidentCandidate, Severity
from signalops.services.incidents import validate_incident_id


class InvestigationRequest(BaseModel):
    incident_id: str | None = Field(default=None, max_length=300)
    question: str | None = Field(default=None, min_length=3, max_length=1000)
    window_minutes: int = Field(default=60, ge=5, le=1440)

    @field_validator("incident_id")
    @classmethod
    def _incident(cls, value: str | None) -> str | None:
        return validate_incident_id(value) if value else None

    @model_validator(mode="after")
    def _something_to_investigate(self) -> InvestigationRequest:
        if not self.incident_id and not self.question:
            raise ValueError("provide an incident_id, a question, or both")
        return self


class EvidenceItem(BaseModel):
    evidence_id: str
    tool: str
    arguments: dict[str, Any]
    retrieved_at: dt.datetime
    ok: bool
    error: str | None = None
    summary: str


class Observation(BaseModel):
    claim: str
    evidence_ids: list[str]
    sources: list[str]
    observed_at: dt.datetime | None


class PotentialCause(BaseModel):
    hypothesis: str
    supporting_evidence: list[str]
    confidence: Literal["low", "medium", "high"]
    status: Literal["hypothesis"] = "hypothesis"


class RunbookCitation(BaseModel):
    title: str
    source: str
    section: str
    relevance: str


class GeneratedBy(BaseModel):
    provider: str
    model: str | None
    uses_llm: bool


class InvestigationReport(BaseModel):
    investigation_id: str
    incident_id: str | None
    question: str | None
    status: Literal["complete", "partial"]
    summary: str
    severity: Severity
    severity_basis: str
    observations: list[Observation]
    potential_causes: list[PotentialCause]
    runbooks: list[RunbookCitation]
    recommended_steps: list[str]
    missing_information: list[str]
    limitations: list[str]
    evidence: list[EvidenceItem]
    validation_notes: list[str]
    generated_by: GeneratedBy
    started_at: dt.datetime
    finished_at: dt.datetime
    tool_calls: int
    confidence_semantics: str = (
        "Confidence is the model's qualitative judgement, adjusted by evidence-count rules; "
        "it is not a calibrated probability."
    )


class InvestigationJob(BaseModel):
    job_id: str
    status: Literal["queued", "running", "succeeded", "failed"]
    created_at: dt.datetime
    updated_at: dt.datetime
    request: InvestigationRequest
    incident: IncidentCandidate | None = None
    report: InvestigationReport | None = None
    error: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# What the model submits (validated, then grounded into InvestigationReport)  #
# --------------------------------------------------------------------------- #

class _SubmittedObservation(BaseModel):
    claim: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(min_length=1, max_length=10)


class _SubmittedCause(BaseModel):
    hypothesis: str = Field(min_length=1, max_length=600)
    supporting_evidence_ids: list[str] = Field(min_length=1, max_length=10)
    confidence: Literal["low", "medium", "high"]


class _SubmittedCitation(BaseModel):
    source: str = Field(max_length=200)
    section: str = Field(max_length=200)
    relevance: str = Field(max_length=400)


class SubmittedReport(BaseModel):
    summary: str = Field(min_length=1, max_length=1500)
    observations: list[_SubmittedObservation] = Field(max_length=20)
    potential_causes: list[_SubmittedCause] = Field(max_length=8)
    runbook_citations: list[_SubmittedCitation] = Field(max_length=8)
    recommended_steps: list[str] = Field(max_length=12)
    missing_information: list[str] = Field(max_length=12)
    limitations: list[str] = Field(max_length=12)


SUBMIT_REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "observations", "potential_causes", "runbook_citations",
                 "recommended_steps", "missing_information", "limitations"],
    "properties": {
        "summary": {"type": "string", "description": "Two to four sentences. No root-cause certainty."},
        "observations": {
            "type": "array",
            "description": "Facts read directly from tool results. Each cites evidence ids.",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["claim", "evidence_ids"],
                "properties": {
                    "claim": {"type": "string"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                },
            },
        },
        "potential_causes": {
            "type": "array",
            "description": "Hypotheses, each supported by evidence ids.",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["hypothesis", "supporting_evidence_ids", "confidence"],
                "properties": {
                    "hypothesis": {"type": "string"},
                    "supporting_evidence_ids": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                },
            },
        },
        "runbook_citations": {
            "type": "array",
            "description": "Only sections returned by search_runbooks in this investigation.",
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["source", "section", "relevance"],
                "properties": {
                    "source": {"type": "string"},
                    "section": {"type": "string"},
                    "relevance": {"type": "string"},
                },
            },
        },
        "recommended_steps": {"type": "array", "items": {"type": "string"}},
        "missing_information": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "array", "items": {"type": "string"}},
    },
}
