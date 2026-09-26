-- Database bootstrap. Runs once, on an empty data directory, via the
-- postgres image's /docker-entrypoint-initdb.d hook.
--
-- Scope is deliberately limited to schemas, extensions and the migration
-- ledger. Table DDL for normalised events and the tamper-evident hash chain
-- arrives in Phase 3 as numbered migrations under db/migrations/, so schema
-- changes are versioned and replayable rather than baked into an init script
-- that only ever executes on a fresh volume.

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Extensions
-- ---------------------------------------------------------------------------

-- digest()/gen_random_bytes() for the SHA-256 evidence chain. Computing the
-- hash in-database means the chain link is written in the same transaction as
-- the row it protects, so a crash cannot leave a record unchained.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Trigram indexing for substring search over raw log messages, which a
-- plain B-tree cannot serve.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---------------------------------------------------------------------------
-- Schemas — one per architectural tier
-- ---------------------------------------------------------------------------

-- Normalised, deduplicated telemetry (3NF: hosts / users / processes /
-- network endpoints as separate relations referenced by an events fact table).
CREATE SCHEMA IF NOT EXISTS evidence;

-- Append-only hash chain sealing the evidence tables.
CREATE SCHEMA IF NOT EXISTS ledger;

-- Model scores, detections and analyst triage state.
CREATE SCHEMA IF NOT EXISTS analytics;

COMMENT ON SCHEMA evidence  IS 'Normalised forensic event store (3NF).';
COMMENT ON SCHEMA ledger    IS 'Tamper-evident append-only SHA-256 hash chain.';
COMMENT ON SCHEMA analytics IS 'Anomaly scores, detections, triage state.';

-- ---------------------------------------------------------------------------
-- Migration tracking
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS public.schema_migrations (
    version      TEXT        PRIMARY KEY,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    checksum     TEXT        NOT NULL,
    description  TEXT
);

COMMENT ON TABLE public.schema_migrations IS
    'Applied migrations from db/migrations, newest wins. checksum guards against edits to already-applied files.';

INSERT INTO public.schema_migrations (version, checksum, description)
VALUES ('0000_bootstrap', 'n/a', 'Schemas, extensions and migration tracking')
ON CONFLICT (version) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Least privilege
-- ---------------------------------------------------------------------------
-- The application connects as a role that can read and write rows but cannot
-- alter structure. Evidence integrity depends on the writer being unable to
-- drop or rewrite the ledger; migrations run separately as the owner.
--
-- Created idempotently: this script runs on a fresh volume, but being
-- re-runnable makes it safe to apply by hand against an existing database.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'forensics_app') THEN
        -- NOLOGIN: this is a privilege bundle, not a login account. Grant it to
        -- a real user with its own password rather than embedding one here.
        CREATE ROLE forensics_app NOLOGIN;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA evidence, ledger, analytics TO forensics_app;

-- Applies to tables created later by migrations, so Phase 3 does not have to
-- remember to re-grant.
ALTER DEFAULT PRIVILEGES IN SCHEMA evidence, analytics
    GRANT SELECT, INSERT, UPDATE ON TABLES TO forensics_app;

-- The ledger is append-only by design: no UPDATE, no DELETE, ever.
ALTER DEFAULT PRIVILEGES IN SCHEMA ledger
    GRANT SELECT, INSERT ON TABLES TO forensics_app;

ALTER DEFAULT PRIVILEGES IN SCHEMA evidence, analytics, ledger
    GRANT USAGE, SELECT ON SEQUENCES TO forensics_app;

-- The bootstrap superuser inherits the app role so Phase 1 can connect
-- immediately; Phase 3 introduces a dedicated login user.
GRANT forensics_app TO CURRENT_USER;
