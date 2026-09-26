# syntax=docker/dockerfile:1.7
#
# Base image for every Python service in the pipeline (producer now; the
# inference and ledger workers in later phases reuse it by overriding CMD).
#
# Multi-stage so the runtime layer carries no pip cache and no build toolchain,
# and runs as an unprivileged user — a container that ingests untrusted log data
# has no business running as root.

# --------------------------------------------------------------------------- #
# Stage 1: dependencies                                                        #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copied alone so the dependency layer is cached until requirements.txt changes,
# not on every source edit.
COPY requirements.txt ./
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install -r requirements.txt

# --------------------------------------------------------------------------- #
# Stage 2: runtime                                                             #
# --------------------------------------------------------------------------- #
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONFAULTHANDLER=1 \
    PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/src

# curl is used by the Compose healthcheck; ca-certificates for any TLS broker.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Fixed uid/gid keeps bind-mounted volume ownership predictable across hosts.
RUN groupadd --system --gid 10001 forensics \
 && useradd --system --uid 10001 --gid forensics --create-home forensics \
 && mkdir -p /var/spool/forensics \
 && chown -R forensics:forensics /var/spool/forensics

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY --chown=forensics:forensics src/ /app/src/
COPY --chown=forensics:forensics pyproject.toml /app/
# Operational entrypoints (migrations, ledger verification) and the migration
# SQL itself are baked in rather than bind-mounted: the image is the deployable
# artifact, and a schema change should require a rebuild, not a mount that makes
# two environments running the same tag behave differently.
COPY --chown=forensics:forensics scripts/ /app/scripts/
COPY --chown=forensics:forensics db/ /app/db/

USER forensics

# Dead-letter spool lives on a volume so records survive container replacement.
VOLUME ["/var/spool/forensics"]

# Overridden per service in docker-compose.yml.
CMD ["python", "-m", "forensics.ingestion.log_producer"]
