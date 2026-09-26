-- 0001: Normalised evidence model (3NF) and the partitioned event fact table.
--
-- Normalisation strategy, and where it deliberately stops:
--
--   * Repeating *entities* (hosts, users, process images, network endpoints,
--     datasets) become their own relations. In a real estate a hostname repeats
--     across millions of rows; storing it once and referencing it removes the
--     update anomaly and shrinks the fact table substantially.
--   * Fixed, closed domains (category, outcome, direction) become ENUM types
--     rather than lookup tables. A lookup table for a three-value domain that
--     changes only when the code changes buys a join and no integrity that the
--     type system was not already giving us.
--   * `action` and `message` stay as columns on the fact. `action` is
--     open-ended, and `message` is the raw log line — the payload the Phase 3
--     model consumes. Neither is a transitive dependency on a non-key
--     attribute, so 3NF does not ask us to move them.

-- NB: no psql meta-commands here. Migrations are applied by
-- scripts/migrate.py through psycopg, which wraps each file in a
-- transaction and aborts on the first error; \set would be a syntax
-- error over the wire protocol. db/init/*.sql runs under psql and may
-- use them.

-- ---------------------------------------------------------------------------
-- Domains
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type t
                   JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'event_category' AND n.nspname = 'evidence') THEN
        CREATE TYPE evidence.event_category AS ENUM
            ('authentication', 'process', 'network', 'file');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t
                   JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'event_outcome' AND n.nspname = 'evidence') THEN
        CREATE TYPE evidence.event_outcome AS ENUM ('success', 'failure', 'unknown');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_type t
                   JOIN pg_namespace n ON n.oid = t.typnamespace
                   WHERE t.typname = 'flow_direction' AND n.nspname = 'evidence') THEN
        CREATE TYPE evidence.flow_direction AS ENUM ('inbound', 'outbound', 'internal');
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Dimensions
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS evidence.hosts (
    host_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    host_name   TEXT        NOT NULL,
    ip          INET,
    os_family   TEXT,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT hosts_host_name_key UNIQUE (host_name)
);

COMMENT ON TABLE evidence.hosts IS
    'One row per machine. host_name is the natural key and the Kafka partition key.';

CREATE TABLE IF NOT EXISTS evidence.users (
    user_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_name   TEXT        NOT NULL,
    uid         INTEGER,
    domain      TEXT        NOT NULL DEFAULT 'corp.local',
    -- The same name in two domains is two different principals.
    CONSTRAINT users_name_domain_key UNIQUE (user_name, domain)
);

CREATE TABLE IF NOT EXISTS evidence.process_images (
    image_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL,
    executable  TEXT,
    -- executable may be NULL, and NULLs are never equal in a UNIQUE index, so
    -- the coalesced expression index below is what actually enforces identity.
    CONSTRAINT process_images_name_exe_key UNIQUE (name, executable)
);

COMMENT ON TABLE evidence.process_images IS
    'Distinct (name, executable) pairs. The volatile part of an execution — pid '
    'and command line — stays on the event, since it does not repeat.';

CREATE UNIQUE INDEX IF NOT EXISTS process_images_identity_uidx
    ON evidence.process_images (name, COALESCE(executable, ''));

-- Keyed on the address alone, NOT on (address, port).
--
-- Ports were tried as part of the key and measured: with random ephemeral
-- source ports, 4 000 events produced 4 039 distinct (ip, port) pairs — a
-- dimension with one row per fact, costing two joins and compressing nothing.
-- The same data holds 1 361 distinct addresses.
--
-- The modelling point is that an address is an entity (it persists, it recurs,
-- and threat intelligence attaches to it), whereas a port is an attribute of a
-- single flow. Ports therefore live on the fact table.
CREATE TABLE IF NOT EXISTS evidence.network_addresses (
    address_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    address     INET        NOT NULL,
    first_seen  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT network_addresses_address_key UNIQUE (address)
);

COMMENT ON TABLE evidence.network_addresses IS
    'Distinct IP addresses observed. The join target for Phase 3 threat-intel enrichment.';

CREATE TABLE IF NOT EXISTS evidence.datasets (
    -- INTEGER, not SMALLINT: the identity range is cheap and a narrow
    -- sequence is only safe while an assumption about cardinality holds.
    dataset_id  INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        TEXT NOT NULL,
    CONSTRAINT datasets_name_key UNIQUE (name)
);

-- ---------------------------------------------------------------------------
-- Fact table
-- ---------------------------------------------------------------------------
--
-- Range-partitioned by occurred_at. Forensic queries are overwhelmingly
-- time-bounded ("what happened between 02:00 and 04:00 on the 9th"), so
-- partition pruning removes most of the table from the plan before it starts.
-- It also makes retention a DROP TABLE instead of a mass DELETE with the
-- vacuum storm that follows.
--
-- A partitioned table's unique constraint must contain the partition key, so
-- the key is (event_id, occurred_at) rather than event_id alone. This still
-- gives idempotent ingestion: occurred_at is carried in the event itself, so a
-- replayed record produces the identical key and conflicts as intended.

CREATE TABLE IF NOT EXISTS evidence.events (
    event_id                UUID        NOT NULL,
    occurred_at             TIMESTAMPTZ NOT NULL,
    ingested_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    category                evidence.event_category NOT NULL,
    action                  TEXT,
    outcome                 evidence.event_outcome,
    severity                SMALLINT,
    message                 TEXT,

    host_id                 BIGINT      NOT NULL REFERENCES evidence.hosts (host_id),
    user_id                 BIGINT      REFERENCES evidence.users (user_id),
    dataset_id              INTEGER     REFERENCES evidence.datasets (dataset_id),

    process_image_id        BIGINT      REFERENCES evidence.process_images (image_id),
    process_pid             INTEGER,
    process_command_line    TEXT,
    process_parent_image_id BIGINT      REFERENCES evidence.process_images (image_id),
    process_parent_pid      INTEGER,

    source_address_id       BIGINT      REFERENCES evidence.network_addresses (address_id),
    source_port             INTEGER,
    destination_address_id  BIGINT      REFERENCES evidence.network_addresses (address_id),
    destination_port        INTEGER,
    protocol                TEXT,
    transport               TEXT,
    bytes_sent              BIGINT,
    bytes_received          BIGINT,
    direction               evidence.flow_direction,

    schema_version          TEXT,
    kafka_partition         INTEGER,
    kafka_offset            BIGINT,

    CONSTRAINT events_pkey PRIMARY KEY (event_id, occurred_at),
    CONSTRAINT events_severity_range CHECK (severity IS NULL OR severity BETWEEN 0 AND 7),
    CONSTRAINT events_bytes_non_negative CHECK (
        (bytes_sent IS NULL OR bytes_sent >= 0)
        AND (bytes_received IS NULL OR bytes_received >= 0)
    ),
    CONSTRAINT events_port_range CHECK (
        (source_port IS NULL OR source_port BETWEEN 0 AND 65535)
        AND (destination_port IS NULL OR destination_port BETWEEN 0 AND 65535)
    )
) PARTITION BY RANGE (occurred_at);

COMMENT ON TABLE evidence.events IS
    'Normalised event fact table, range-partitioned monthly on occurred_at.';
COMMENT ON COLUMN evidence.events.occurred_at IS
    'Event time from the source. Windows and retention key off this, never ingested_at.';
COMMENT ON COLUMN evidence.events.message IS
    'Raw unstructured log line — the input to the Phase 3 sequence model.';

-- ---------------------------------------------------------------------------
-- Partition management
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION evidence.ensure_month_partition(
    target_month DATE
) RETURNS TEXT
LANGUAGE plpgsql
AS $$
DECLARE
    start_bound DATE := date_trunc('month', target_month)::DATE;
    end_bound   DATE := (date_trunc('month', target_month) + INTERVAL '1 month')::DATE;
    part_name   TEXT := format('events_%s', to_char(start_bound, 'YYYY_MM'));
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = part_name AND n.nspname = 'evidence'
    ) THEN
        RETURN part_name;
    END IF;

    EXECUTE format(
        'CREATE TABLE evidence.%I PARTITION OF evidence.events '
        'FOR VALUES FROM (%L) TO (%L)',
        part_name, start_bound, end_bound
    );

    -- BRIN, not B-tree, for the time column: rows arrive in occurred_at order,
    -- so block ranges correlate tightly with time. The index is a few kilobytes
    -- against a B-tree's hundreds of megabytes at scale, and range scans are
    -- what forensic queries do.
    EXECUTE format(
        'CREATE INDEX %I ON evidence.%I USING BRIN (occurred_at) '
        'WITH (pages_per_range = 32)',
        part_name || '_occurred_at_brin', part_name
    );

    RETURN part_name;
END;
$$;

COMMENT ON FUNCTION evidence.ensure_month_partition(DATE) IS
    'Idempotently create the monthly partition (and its BRIN index) covering the given date.';

-- A DEFAULT partition catches rows outside every declared range, so an event
-- with an unexpected timestamp is stored and visible rather than rejected at
-- insert time. It must be kept small: rows here are not pruned.
CREATE TABLE IF NOT EXISTS evidence.events_default PARTITION OF evidence.events DEFAULT;

-- ---------------------------------------------------------------------------
-- Indexes on the parent (propagated to every partition)
-- ---------------------------------------------------------------------------

-- "Show me this host's timeline" — the single most common investigation query.
CREATE INDEX IF NOT EXISTS events_host_time_idx
    ON evidence.events (host_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS events_category_time_idx
    ON evidence.events (category, occurred_at DESC);

-- Partial index: failures are a small fraction of rows but the starting point
-- of most authentication investigations, so the index stays small and hot.
CREATE INDEX IF NOT EXISTS events_failures_idx
    ON evidence.events (occurred_at DESC)
    WHERE outcome = 'failure';

CREATE INDEX IF NOT EXISTS events_user_time_idx
    ON evidence.events (user_id, occurred_at DESC)
    WHERE user_id IS NOT NULL;

-- "Who else talked to this address?" — the pivot after a bad IP is identified.
CREATE INDEX IF NOT EXISTS events_destination_time_idx
    ON evidence.events (destination_address_id, occurred_at DESC)
    WHERE destination_address_id IS NOT NULL;

-- Trigram index for substring search over raw log lines ("find every command
-- mentioning /dev/tcp"). A B-tree cannot serve a leading-wildcard LIKE.
CREATE INDEX IF NOT EXISTS events_message_trgm_idx
    ON evidence.events USING GIN (message gin_trgm_ops);
