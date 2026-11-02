"""Asynchronous investigation jobs.

Investigations run on a small bounded thread pool, never on a request thread,
so a slow or failing LLM cannot hold an API worker, a Slack acknowledgement or
the health endpoint. Jobs are kept in memory (bounded, newest first); they are
lost on restart, which is acceptable for a read-only advisory feature and is
documented as a limitation.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from forensics.common.logging import get_logger
from signalops.investigation.agent import InvestigationFailed, Investigator
from signalops.investigation.schemas import EvidenceItem, InvestigationJob, InvestigationRequest
from signalops.models import IncidentCandidate, utcnow

logger = get_logger(__name__, component="signalops-investigations")

MAX_JOBS = 200


class InvestigationQueueFull(RuntimeError):
    pass


class InvestigationJobs:
    def __init__(self, investigator: Investigator, *, workers: int = 2, max_pending: int = 10) -> None:
        self._investigator = investigator
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="investigation")
        self._lock = threading.Lock()
        self._jobs: OrderedDict[str, InvestigationJob] = OrderedDict()
        self._max_pending = max_pending
        self._listeners: dict[str, list[Callable[[InvestigationJob], None]]] = {}

    def submit(self, request: InvestigationRequest, incident: IncidentCandidate | None,
               on_done: Callable[[InvestigationJob], None] | None = None) -> InvestigationJob:
        now = utcnow()
        job = InvestigationJob(job_id=uuid.uuid4().hex, status="queued", created_at=now,
                               updated_at=now, request=request, incident=incident)
        with self._lock:
            active = sum(1 for j in self._jobs.values() if j.status in {"queued", "running"})
            if active >= self._max_pending:
                raise InvestigationQueueFull("too many investigations in progress; try again later")
            self._jobs[job.job_id] = job
            while len(self._jobs) > MAX_JOBS:
                self._jobs.popitem(last=False)
            if on_done is not None:
                self._listeners[job.job_id] = [on_done]
        self._pool.submit(self._run, job.job_id)
        return job.model_copy(deep=True)

    def get(self, job_id: str) -> InvestigationJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return job.model_copy(deep=True) if job else None

    def _update(self, job_id: str, **changes: object) -> InvestigationJob | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            for key, value in changes.items():
                setattr(job, key, value)
            job.updated_at = utcnow()
            return job.model_copy(deep=True)

    def _run(self, job_id: str) -> None:
        job = self._update(job_id, status="running")
        if job is None:
            return

        def progress(evidence: list[EvidenceItem]) -> None:
            self._update(job_id, evidence=evidence)

        try:
            report = self._investigator.run(job.request, job.incident, investigation_id=job_id,
                                            on_progress=progress)
            final = self._update(job_id, status="succeeded", report=report, evidence=report.evidence)
        except InvestigationFailed as exc:
            logger.warning("Investigation failed", extra={"job_id": job_id, "reason": str(exc)})
            final = self._update(job_id, status="failed", error=str(exc), evidence=exc.evidence)
        except Exception as exc:  # noqa: BLE001 - a job must always reach a terminal state
            logger.error("Investigation crashed", extra={"job_id": job_id}, exc_info=True)
            final = self._update(job_id, status="failed",
                                 error=f"internal error ({exc.__class__.__name__})")
        for listener in self._listeners.pop(job_id, []):
            try:
                if final is not None:
                    listener(final)
            except Exception:  # noqa: BLE001 - notification is best effort
                logger.warning("Investigation listener failed", extra={"job_id": job_id}, exc_info=True)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
