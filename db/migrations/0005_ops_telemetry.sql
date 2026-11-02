-- 0005: Operational telemetry for SignalOps.
--
-- NB: no psql meta-commands here; applied by scripts/migrate.py through psycopg.
--
-- Two signals the pipeline already computes but only ever wrote to a log line:
--
--   * Spark Structured Streaming progress. Spark reports it per micro-batch to
--     an in-process listener and nowhere else - the UI's REST API does not
--     expose Structured Streaming progress - so without a durable copy the
--     operational layer could only guess at processing rates and lag.
--   * Ledger verification outcomes. The sealer runs a full out-of-database
--     verification every N cycles; its result was logged and then lost.
--
-- Both live in their own `ops` schema. They are observations about the
-- pipeline, not evidence, so they must not sit under the hash chain, and they
-- are prunable where evidence is not.

CREATE SCHEMA IF NOT EXISTS ops;

COMMENT ON SCHEMA ops IS
    'Pipeline self-observation (stream progress, ledger verification runs). Not evidence.';

-- ---------------------------------------------------------------------------
-- Stream query state: one row per named query, upserted on every listener event
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ops.stream_queries (
    query_name        TEXT        PRIMARY KEY,
    query_id          TEXT        NOT NULL,
    run_id            TEXT        NOT NULL,
    -- 'active' after start or progress, 'idle' when Spark reports no new data,
    -- 'terminated' once the query stops (with exception text if it failed).
    status            TEXT        NOT NULL,
    started_at        TIMESTAMPTZ,
    last_event_at     TIMESTAMPTZ NOT NULL,
    last_progress_at  TIMESTAMPTZ,
    last_batch_id     BIGINT,
    exception         TEXT,
    CONSTRAINT stream_queries_status_check
        CHECK (status IN ('active', 'idle', 'terminated'))
);

COMMENT ON TABLE ops.stream_queries IS
    'Latest lifecycle state per Spark streaming query, written by the driver-side listener.';

-- ---------------------------------------------------------------------------
-- Stream progress history: one row per completed micro-batch
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ops.stream_progress (
    progress_id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    query_name                 TEXT        NOT NULL,
    query_id                   TEXT        NOT NULL,
    run_id                     TEXT        NOT NULL,
    batch_id                   BIGINT      NOT NULL,
    -- Spark's own trigger timestamp for the batch, not the insert time.
    batch_timestamp            TIMESTAMPTZ NOT NULL,
    recorded_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    num_input_rows             BIGINT,
    input_rows_per_second      DOUBLE PRECISION,
    processed_rows_per_second  DOUBLE PRECISION,
    trigger_execution_ms       BIGINT,
    -- Max over Kafka sources of (latest available offset - batch end offset),
    -- summed across partitions by Spark. NULL when Spark did not report it.
    max_offsets_behind_latest  BIGINT,
    watermark                  TIMESTAMPTZ,
    -- -1 from Spark means "sink does not report"; stored as NULL.
    sink_output_rows           BIGINT,
    sources                    JSONB,
    CONSTRAINT stream_progress_batch_key UNIQUE (run_id, batch_id)
);

COMMENT ON TABLE ops.stream_progress IS
    'StreamingQueryProgress per micro-batch. Retention is enforced by the writer.';

CREATE INDEX IF NOT EXISTS stream_progress_query_time_idx
    ON ops.stream_progress (query_name, batch_timestamp DESC);

CREATE INDEX IF NOT EXISTS stream_progress_time_idx
    ON ops.stream_progress USING BRIN (batch_timestamp);

-- ---------------------------------------------------------------------------
-- Ledger verification runs
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ops.ledger_verifications (
    verification_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at        TIMESTAMPTZ NOT NULL,
    finished_at       TIMESTAMPTZ NOT NULL,
    intact            BOOLEAN     NOT NULL,
    events_checked    BIGINT      NOT NULL,
    blocks_checked    BIGINT      NOT NULL,
    unsealed_events   BIGINT      NOT NULL,
    finding_count     INTEGER     NOT NULL,
    -- The first findings only; the full list is in the sealer's log.
    findings          JSONB       NOT NULL DEFAULT '[]',
    verifier          TEXT        NOT NULL DEFAULT 'sealer'
);

COMMENT ON TABLE ops.ledger_verifications IS
    'Outcome of each full out-of-database ledger verification (forensics.ledger.verifier).';

CREATE INDEX IF NOT EXISTS ledger_verifications_finished_idx
    ON ops.ledger_verifications (finished_at DESC);

-- ---------------------------------------------------------------------------
-- Supporting index on the landing table
-- ---------------------------------------------------------------------------
-- The operational layer buckets landed rows by time ("how many records reached
-- Postgres per minute over the last hour"). landed_at is insert-ordered, so a
-- BRIN index serves those range scans for a few kilobytes.

CREATE INDEX IF NOT EXISTS raw_events_landed_at_brin
    ON evidence.raw_events USING BRIN (landed_at);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

GRANT USAGE ON SCHEMA ops TO forensics_app;
GRANT SELECT, INSERT, UPDATE ON ops.stream_queries TO forensics_app;
GRANT SELECT, INSERT, DELETE ON ops.stream_progress TO forensics_app;
GRANT SELECT, INSERT ON ops.ledger_verifications TO forensics_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA ops TO forensics_app;
