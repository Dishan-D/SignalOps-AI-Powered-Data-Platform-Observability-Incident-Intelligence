-- 0003: Detection tier — log templates, model runs and scored detections.
--
-- NB: no psql meta-commands here; applied by scripts/migrate.py through psycopg.
--
-- Everything lives in `analytics`, never `evidence`. Evidence is what the system
-- observed and is sealed by the Phase 4 hash chain; a detection is an opinion
-- about that evidence, produced by a specific model version, and revisable when
-- a better model arrives. Mixing the two would mean re-scoring history mutates
-- the record the chain protects.

-- ---------------------------------------------------------------------------
-- Model runs
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analytics.model_runs (
    run_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    model_version   TEXT        NOT NULL,
    trained_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    window_size     INTEGER     NOT NULL,
    stride          INTEGER     NOT NULL,
    vocabulary_size INTEGER     NOT NULL,
    template_count  INTEGER     NOT NULL,
    -- Calibrated cuts, one per decision signal. JSONB because the signal set is
    -- a modelling decision that will change; a column per signal would mean a
    -- migration every time someone adds one.
    thresholds      JSONB       NOT NULL,
    target_fpr      DOUBLE PRECISION,
    metrics         JSONB,
    CONSTRAINT model_runs_version_key UNIQUE (model_version)
);

COMMENT ON TABLE analytics.model_runs IS
    'One row per trained detector. Detections reference the run that produced them.';

-- ---------------------------------------------------------------------------
-- Log templates
-- ---------------------------------------------------------------------------
-- The mined vocabulary, persisted so an analyst can read what a token id means
-- and so template drift is visible over time.

CREATE TABLE IF NOT EXISTS analytics.log_templates (
    run_id          BIGINT      NOT NULL REFERENCES analytics.model_runs (run_id) ON DELETE CASCADE,
    template_id     INTEGER     NOT NULL,
    template        TEXT        NOT NULL,
    occurrence_count BIGINT     NOT NULL DEFAULT 0,
    CONSTRAINT log_templates_pkey PRIMARY KEY (run_id, template_id)
);

-- Substring search over templates ("which template covers /dev/tcp?").
CREATE INDEX IF NOT EXISTS log_templates_text_trgm_idx
    ON analytics.log_templates USING GIN (template gin_trgm_ops);

-- ---------------------------------------------------------------------------
-- Detections
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS analytics.detections (
    detection_id    BIGINT GENERATED ALWAYS AS IDENTITY,
    run_id          BIGINT      NOT NULL REFERENCES analytics.model_runs (run_id),
    host_name       TEXT        NOT NULL,
    window_start    TIMESTAMPTZ NOT NULL,
    window_end      TIMESTAMPTZ NOT NULL,
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Raw per-signal values, kept alongside the verdict. An analyst asking
    -- "why did this fire?" needs the numbers, not just the boolean, and a
    -- threshold change must be re-evaluable without re-running the model.
    signals         JSONB       NOT NULL,
    -- Largest signal as a multiple of its own cut: >= 1.0 means alerting.
    score           DOUBLE PRECISION NOT NULL,
    flagged         BOOLEAN     NOT NULL,

    -- The events this window covered, so a detection links back to evidence.
    event_ids       UUID[]      NOT NULL DEFAULT '{}',

    CONSTRAINT detections_pkey PRIMARY KEY (detection_id, window_start),
    -- One verdict per (run, host, window), so an at-least-once consumer that
    -- re-scores a window inserts nothing the second time. detection_id is
    -- deliberately NOT part of this constraint — including the surrogate key
    -- would make every row trivially unique and the guard useless. window_start
    -- is present because a partitioned table's unique constraint must contain
    -- the partition key.
    CONSTRAINT detections_unique_window UNIQUE (run_id, host_name, window_start)
) PARTITION BY RANGE (window_start);

COMMENT ON TABLE analytics.detections IS
    'Model verdicts per (host, window). Partitioned monthly like evidence.events.';
COMMENT ON COLUMN analytics.detections.score IS
    'Largest decision signal divided by its calibrated cut; >= 1.0 means flagged.';

CREATE TABLE IF NOT EXISTS analytics.detections_default
    PARTITION OF analytics.detections DEFAULT;

CREATE OR REPLACE FUNCTION analytics.ensure_detection_partition(target_month DATE)
RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    start_bound DATE := date_trunc('month', target_month)::DATE;
    end_bound   DATE := (date_trunc('month', target_month) + INTERVAL '1 month')::DATE;
    part_name   TEXT := format('detections_%s', to_char(start_bound, 'YYYY_MM'));
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = part_name AND n.nspname = 'analytics'
    ) THEN
        RETURN part_name;
    END IF;

    EXECUTE format(
        'CREATE TABLE analytics.%I PARTITION OF analytics.detections '
        'FOR VALUES FROM (%L) TO (%L)', part_name, start_bound, end_bound
    );
    RETURN part_name;
END;
$$;

-- The triage queue: open alerts, newest first. Partial, because unflagged
-- windows are the overwhelming majority and nobody queries them by time.
CREATE INDEX IF NOT EXISTS detections_flagged_idx
    ON analytics.detections (window_start DESC)
    WHERE flagged;

CREATE INDEX IF NOT EXISTS detections_host_window_idx
    ON analytics.detections (host_name, window_start DESC);

CREATE INDEX IF NOT EXISTS detections_score_idx
    ON analytics.detections (score DESC)
    WHERE flagged;

-- ---------------------------------------------------------------------------
-- Evaluation view
-- ---------------------------------------------------------------------------
-- Joins verdicts to ground truth so precision/recall can be computed in SQL
-- against what actually landed in the database, rather than only in the
-- training harness where a bug would be invisible.

CREATE OR REPLACE VIEW analytics.detection_truth AS
SELECT
    d.detection_id,
    d.run_id,
    d.host_name,
    d.window_start,
    d.window_end,
    d.score,
    d.flagged,
    -- A window is a true positive if ANY event it covered was an attack, which
    -- is the same rule the training harness uses.
    EXISTS (
        SELECT 1 FROM analytics.event_labels l
        WHERE l.event_id = ANY (d.event_ids) AND l.is_anomaly
    ) AS is_anomaly
FROM analytics.detections d;

COMMENT ON VIEW analytics.detection_truth IS
    'Detections joined to synthetic ground truth. Evaluation only — labels are never model inputs.';

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT ON analytics.model_runs, analytics.log_templates TO forensics_app;
GRANT SELECT, INSERT ON analytics.detections TO forensics_app;
GRANT SELECT ON analytics.detection_truth TO forensics_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA analytics TO forensics_app;
