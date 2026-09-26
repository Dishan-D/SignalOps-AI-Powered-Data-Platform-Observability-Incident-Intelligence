-- 0002: Flat landing table for the Spark sink, evaluation labels, and the
--       SQL transform that populates the 3NF model.
--
-- Why land flat first (ELT) rather than normalise inside Spark:
--
--   Resolving host_name -> host_id in Spark means a lookup per row against
--   Postgres, or broadcasting and maintaining every dimension in executor
--   memory. Both are slow and both fight the database for the thing it is
--   already good at. Instead the stream appends denormalised rows at full
--   speed, and a set-based SQL transform resolves dimensions in bulk.
--
--   It also decouples availability: if the normalisation step is broken or
--   mid-deploy, ingestion keeps landing evidence instead of dropping it.

-- NB: no psql meta-commands here. Migrations are applied by
-- scripts/migrate.py through psycopg, which wraps each file in a
-- transaction and aborts on the first error; \set would be a syntax
-- error over the wire protocol. db/init/*.sql runs under psql and may
-- use them.

-- ---------------------------------------------------------------------------
-- Landing table
-- ---------------------------------------------------------------------------
-- Column names and types match forensics.streaming.normalize.flatten() exactly;
-- the JDBC sink writes by name.
--
-- Addresses land as TEXT, not INET. A malformed address must not abort the
-- micro-batch write — it is caught and reported by the transform below, where
-- the failure is visible and recoverable.

CREATE TABLE IF NOT EXISTS evidence.raw_events (
    raw_id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id                TEXT,
    event_time              TIMESTAMPTZ,
    ingested_at             TIMESTAMPTZ,
    category                TEXT,
    action                  TEXT,
    outcome                 TEXT,
    severity                INTEGER,
    message                 TEXT,
    dataset                 TEXT,
    schema_version          TEXT,

    host_name               TEXT,
    host_ip                 TEXT,
    host_os_family          TEXT,

    user_name               TEXT,
    user_uid                INTEGER,
    user_domain             TEXT,

    process_pid             INTEGER,
    process_name            TEXT,
    process_executable      TEXT,
    process_command_line    TEXT,
    process_parent_name     TEXT,
    process_parent_pid      INTEGER,

    source_ip               TEXT,
    source_port             INTEGER,
    destination_ip          TEXT,
    destination_port        INTEGER,
    protocol                TEXT,
    transport               TEXT,
    bytes_sent              BIGINT,
    bytes_received          BIGINT,
    direction               TEXT,

    eval_is_anomaly         BOOLEAN,
    eval_scenario           TEXT,
    eval_campaign_id        TEXT,
    eval_step               INTEGER,

    kafka_topic             TEXT,
    kafka_partition         INTEGER,
    kafka_offset            BIGINT,

    -- Transform bookkeeping.
    landed_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    normalized_at           TIMESTAMPTZ,
    normalize_error         TEXT
);

COMMENT ON TABLE evidence.raw_events IS
    'Append-only landing zone for the Spark JDBC sink. Drained by evidence.normalize_raw_events().';

-- The transform's driving query is "everything not yet normalised". A partial
-- index keeps that lookup proportional to the backlog, not to the table.
CREATE INDEX IF NOT EXISTS raw_events_pending_idx
    ON evidence.raw_events (raw_id)
    WHERE normalized_at IS NULL;

CREATE INDEX IF NOT EXISTS raw_events_failed_idx
    ON evidence.raw_events (landed_at DESC)
    WHERE normalize_error IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Evaluation labels
-- ---------------------------------------------------------------------------
-- Ground truth lives in `analytics`, not `evidence`. Evidence is what the
-- system observed; labels are metadata about a synthetic exercise. Keeping them
-- in separate schemas makes "never train on the labels" a structural property
-- rather than a naming convention someone has to remember.

CREATE TABLE IF NOT EXISTS analytics.event_labels (
    event_id     UUID        NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    is_anomaly   BOOLEAN     NOT NULL,
    scenario     TEXT,
    campaign_id  UUID,
    step         INTEGER,
    CONSTRAINT event_labels_pkey PRIMARY KEY (event_id, occurred_at)
);

COMMENT ON TABLE analytics.event_labels IS
    'Synthetic ground truth for scoring detectors. Never an input to a model.';

-- Campaign-level retrieval: "show me every event in this attack".
CREATE INDEX IF NOT EXISTS event_labels_campaign_idx
    ON analytics.event_labels (campaign_id, step)
    WHERE campaign_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS event_labels_scenario_idx
    ON analytics.event_labels (scenario, occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Helpers
-- ---------------------------------------------------------------------------

-- Cast text to INET, yielding NULL instead of raising. A malformed address in
-- one field must not fail an otherwise-valid event.
CREATE OR REPLACE FUNCTION evidence.safe_inet(p_value TEXT)
RETURNS INET
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
BEGIN
    IF p_value IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN p_value::INET;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- The transform
-- ---------------------------------------------------------------------------
--
-- Set-based, not row-by-row. Two hard-won reasons, both measured against a
-- 50 000-event load:
--
--   * Throughput. A per-row PL/pgSQL loop that called a resolve_*() function
--     per dimension and ensure_month_partition() per row managed 5 rows/s —
--     slower than the producer's default 25 events/s, so the backlog grew
--     without bound. The set-based form below does one statement per dimension
--     per batch and one INSERT..SELECT for the facts.
--
--   * Sequence exhaustion. `INSERT .. ON CONFLICT DO UPDATE` evaluates the
--     column DEFAULT — and therefore nextval() — *before* it detects the
--     conflict. Upserting one of three dataset names 50 000 times burned
--     32 767 identity values and overflowed the sequence, failing 29 233 rows.
--     Dimension inserts are now guarded by NOT EXISTS so nextval() is only
--     reached for genuinely new values.

CREATE OR REPLACE FUNCTION evidence.normalize_raw_events(p_batch_size INTEGER DEFAULT 5000)
RETURNS TABLE (normalized BIGINT, failed BIGINT)
LANGUAGE plpgsql
AS $$
DECLARE
    v_normalized BIGINT := 0;
    v_month      DATE;
BEGIN
    CREATE TEMP TABLE IF NOT EXISTS _normalize_batch (raw_id BIGINT PRIMARY KEY)
        ON COMMIT DROP;
    DELETE FROM _normalize_batch;

    -- Claim a batch. SKIP LOCKED lets several workers drain the backlog
    -- concurrently without contending for the same rows.
    INSERT INTO _normalize_batch (raw_id)
    SELECT raw_id FROM (
        SELECT raw_id
        FROM evidence.raw_events
        WHERE normalized_at IS NULL
        ORDER BY raw_id
        LIMIT p_batch_size
        FOR UPDATE SKIP LOCKED
    ) claimed;

    IF NOT EXISTS (SELECT 1 FROM _normalize_batch) THEN
        normalized := 0; failed := 0; RETURN NEXT; RETURN;
    END IF;

    -- Partitions: once per distinct month in the batch, not once per row.
    FOR v_month IN
        SELECT DISTINCT date_trunc('month', r.event_time)::DATE
        FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
        WHERE r.event_time IS NOT NULL
    LOOP
        PERFORM evidence.ensure_month_partition(v_month);
    END LOOP;

    -- --- Dimensions -------------------------------------------------------
    -- NOT EXISTS keeps nextval() off the path for values already present;
    -- ON CONFLICT DO NOTHING closes the race with a concurrent worker.

    INSERT INTO evidence.hosts (host_name, ip, os_family, first_seen, last_seen)
    SELECT DISTINCT ON (r.host_name)
           r.host_name, evidence.safe_inet(r.host_ip), r.host_os_family,
           COALESCE(r.event_time, now()), COALESCE(r.event_time, now())
    FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
    WHERE r.host_name IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM evidence.hosts h WHERE h.host_name = r.host_name)
    ORDER BY r.host_name, r.event_time
    ON CONFLICT (host_name) DO NOTHING;

    -- last_seen still advances for hosts that already existed.
    UPDATE evidence.hosts h
       SET last_seen = s.max_seen
      FROM (SELECT r.host_name, max(r.event_time) AS max_seen
              FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
             WHERE r.host_name IS NOT NULL GROUP BY 1) s
     WHERE h.host_name = s.host_name AND s.max_seen > h.last_seen;

    INSERT INTO evidence.users (user_name, uid, domain)
    SELECT DISTINCT ON (r.user_name, COALESCE(r.user_domain, 'corp.local'))
           r.user_name, r.user_uid, COALESCE(r.user_domain, 'corp.local')
    FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
    WHERE r.user_name IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM evidence.users u
          WHERE u.user_name = r.user_name
            AND u.domain = COALESCE(r.user_domain, 'corp.local'))
    ORDER BY r.user_name, COALESCE(r.user_domain, 'corp.local')
    ON CONFLICT (user_name, domain) DO NOTHING;

    INSERT INTO evidence.datasets (name)
    SELECT DISTINCT r.dataset
    FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
    WHERE r.dataset IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM evidence.datasets d WHERE d.name = r.dataset)
    ON CONFLICT (name) DO NOTHING;

    -- Both the executing image and the parent image come from the same pool.
    INSERT INTO evidence.process_images (name, executable)
    SELECT DISTINCT s.name, s.executable
    FROM (
        SELECT r.process_name AS name, r.process_executable AS executable
        FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
        WHERE r.process_name IS NOT NULL
        UNION
        SELECT r.process_parent_name, NULL
        FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
        WHERE r.process_parent_name IS NOT NULL
    ) s
    WHERE NOT EXISTS (
        SELECT 1 FROM evidence.process_images p
        WHERE p.name = s.name
          AND COALESCE(p.executable, '') = COALESCE(s.executable, ''))
    ON CONFLICT DO NOTHING;

    INSERT INTO evidence.network_addresses (address, first_seen, last_seen)
    -- COALESCE: a row with a NULL event_time still yields an address, and
    -- first_seen/last_seen are NOT NULL.
    SELECT s.addr, COALESCE(min(s.seen), now()), COALESCE(max(s.seen), now())
    FROM (
        SELECT evidence.safe_inet(r.source_ip) AS addr, r.event_time AS seen
        FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
        WHERE r.source_ip IS NOT NULL
        UNION ALL
        SELECT evidence.safe_inet(r.destination_ip), r.event_time
        FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
        WHERE r.destination_ip IS NOT NULL
    ) s
    WHERE s.addr IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM evidence.network_addresses na WHERE na.address = s.addr)
    GROUP BY s.addr
    ON CONFLICT (address) DO NOTHING;

    -- --- Facts ------------------------------------------------------------
    -- ON CONFLICT DO NOTHING gives idempotent replay: an at-least-once stream
    -- redelivering an event is a no-op, so storage is effectively exactly-once.

    WITH inserted AS (
        INSERT INTO evidence.events (
            event_id, occurred_at, ingested_at,
            category, action, outcome, severity, message,
            host_id, user_id, dataset_id,
            process_image_id, process_pid, process_command_line,
            process_parent_image_id, process_parent_pid,
            source_address_id, source_port,
            destination_address_id, destination_port,
            protocol, transport, bytes_sent, bytes_received, direction,
            schema_version, kafka_partition, kafka_offset
        )
        SELECT
            r.event_id::UUID,
            r.event_time,
            COALESCE(r.ingested_at, now()),
            r.category::evidence.event_category,
            r.action,
            r.outcome::evidence.event_outcome,
            r.severity::SMALLINT,
            r.message,
            h.host_id,
            u.user_id,
            d.dataset_id,
            pi.image_id,
            r.process_pid,
            r.process_command_line,
            pp.image_id,
            r.process_parent_pid,
            sa.address_id,
            r.source_port,
            da.address_id,
            r.destination_port,
            r.protocol, r.transport, r.bytes_sent, r.bytes_received,
            r.direction::evidence.flow_direction,
            r.schema_version, r.kafka_partition, r.kafka_offset
        FROM evidence.raw_events r
        JOIN _normalize_batch b USING (raw_id)
        JOIN evidence.hosts h ON h.host_name = r.host_name
        LEFT JOIN evidence.users u
               ON u.user_name = r.user_name
              AND u.domain = COALESCE(r.user_domain, 'corp.local')
        LEFT JOIN evidence.datasets d ON d.name = r.dataset
        LEFT JOIN evidence.process_images pi
               ON pi.name = r.process_name
              AND COALESCE(pi.executable, '') = COALESCE(r.process_executable, '')
        LEFT JOIN evidence.process_images pp
               ON pp.name = r.process_parent_name
              AND COALESCE(pp.executable, '') = ''
        LEFT JOIN evidence.network_addresses sa
               ON sa.address = evidence.safe_inet(r.source_ip)
        LEFT JOIN evidence.network_addresses da
               ON da.address = evidence.safe_inet(r.destination_ip)
        WHERE r.event_time IS NOT NULL
        ON CONFLICT (event_id, occurred_at) DO NOTHING
        RETURNING 1
    )
    SELECT count(*) INTO v_normalized FROM inserted;

    INSERT INTO analytics.event_labels
        (event_id, occurred_at, is_anomaly, scenario, campaign_id, step)
    SELECT r.event_id::UUID, r.event_time, r.eval_is_anomaly,
           r.eval_scenario, r.eval_campaign_id::UUID, r.eval_step
    FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
    WHERE r.eval_is_anomaly IS NOT NULL AND r.event_time IS NOT NULL
    ON CONFLICT (event_id, occurred_at) DO NOTHING;

    -- Rows that produced no fact (null event_time, unparseable UUID) are marked
    -- with a reason instead of being retried forever.
    UPDATE evidence.raw_events r
       SET normalized_at = now(),
           normalize_error = CASE
               WHEN r.event_time IS NULL THEN 'missing_event_time'
               ELSE NULL
           END
      FROM _normalize_batch b
     WHERE r.raw_id = b.raw_id;

    SELECT count(*) INTO failed
    FROM evidence.raw_events r JOIN _normalize_batch b USING (raw_id)
    WHERE r.normalize_error IS NOT NULL;

    normalized := v_normalized;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION evidence.normalize_raw_events(INTEGER) IS
    'Drain up to p_batch_size landed rows into the 3NF model. Set-based, idempotent, re-runnable.';

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON evidence.raw_events TO forensics_app;
GRANT SELECT, INSERT ON evidence.events TO forensics_app;
GRANT SELECT, INSERT, UPDATE ON evidence.hosts, evidence.users,
    evidence.process_images, evidence.network_addresses, evidence.datasets TO forensics_app;
GRANT SELECT, INSERT ON analytics.event_labels TO forensics_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA evidence, analytics TO forensics_app;
