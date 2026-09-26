-- 0004: Tamper-evident append-only evidence ledger.
--
-- NB: no psql meta-commands here; applied by scripts/migrate.py through psycopg.
--
-- ============================================================================
-- Why blocks, and not a per-row hash chain
-- ============================================================================
-- The obvious design — every row's hash includes the previous row's hash —
-- requires a strict total order over inserts. Enforcing that means serialising
-- every write behind a lock on the chain head, which would turn the bulk path
-- into a single-writer queue. The two-layer design below costs 34% instead
-- (12 400 -> 8 200 rows/s, same 50 000 events, trigger disabled then enabled).
--
-- Instead the ledger has two layers:
--
--   1. **Per-event digest**, computed in the SAME transaction as the insert by
--      a statement-level trigger. It depends only on the row's own content, so
--      no ordering and no lock is needed, and no committed event can exist
--      without one.
--   2. **Merkle-rooted blocks**, chained. Sealing batches the digests of
--      unsealed events into a block, computes a Merkle root over them, and
--      hashes that root together with the previous block's hash.
--
-- Tampering is caught at whichever layer it targets:
--   * edit an event      -> its recomputed digest no longer matches
--   * edit a digest      -> the block's Merkle root no longer matches
--   * edit a block       -> every later block hash no longer matches
--   * delete an event    -> its digest is orphaned; the block's count disagrees
--
-- The honest gap: an event is unsealed between insert and the next seal, where
-- a simultaneous edit to both row and digest would go undetected. Sealing runs
-- per ingest batch to keep that window small, and ledger.unsealed_events()
-- reports it.

-- ---------------------------------------------------------------------------
-- Canonical serialisation
-- ---------------------------------------------------------------------------
-- Length-prefixed, never delimiter-separated. A plain separator is forgeable:
-- `message` is attacker-influenced text, so a crafted log line containing the
-- delimiter could shift field boundaries and produce a colliding canonical form
-- for different data. Prefixing each field with its BYTE length (octet_length,
-- not length -- multibyte characters must not change the framing) makes the
-- encoding unambiguous.
--
-- NULL is encoded as length -1, which no real value can produce, so NULL is
-- distinguishable from the empty string.

CREATE OR REPLACE FUNCTION ledger.encode_field(p_value TEXT)
RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT CASE
        WHEN p_value IS NULL THEN '-1:'
        ELSE octet_length(p_value)::TEXT || ':' || p_value
    END;
$$;

-- Timestamps are rendered UTC with microsecond precision. Any locale- or
-- session-dependent rendering would make the digest depend on who computed it.
CREATE OR REPLACE FUNCTION ledger.encode_timestamp(p_value TIMESTAMPTZ)
RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT ledger.encode_field(
        CASE WHEN p_value IS NULL THEN NULL
        ELSE to_char(p_value AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')
        END
    );
$$;

-- ---------------------------------------------------------------------------
-- Per-event digest
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ledger.event_digests (
    event_id     UUID        NOT NULL,
    occurred_at  TIMESTAMPTZ NOT NULL,
    -- SHA-256 over the canonical form, with a leaf domain-separation prefix.
    digest       BYTEA       NOT NULL,
    digested_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    block_id     BIGINT,
    CONSTRAINT event_digests_pkey PRIMARY KEY (event_id, occurred_at),
    CONSTRAINT event_digests_length CHECK (octet_length(digest) = 32)
);

COMMENT ON TABLE ledger.event_digests IS
    'One digest per event, written in the same transaction as the event itself.';

-- Sealing scans for unsealed digests in insertion order.
CREATE INDEX IF NOT EXISTS event_digests_unsealed_idx
    ON ledger.event_digests (digested_at)
    WHERE block_id IS NULL;

CREATE INDEX IF NOT EXISTS event_digests_block_idx
    ON ledger.event_digests (block_id);

-- ---------------------------------------------------------------------------
-- Chained blocks
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS ledger.chain_blocks (
    block_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Dense, gap-free ordering. A missing sequence number is itself evidence
    -- that a block was removed.
    sequence_number BIGINT      NOT NULL,
    prev_hash       BYTEA       NOT NULL,
    merkle_root     BYTEA       NOT NULL,
    block_hash      BYTEA       NOT NULL,
    event_count     INTEGER     NOT NULL,
    first_event_at  TIMESTAMPTZ,
    last_event_at   TIMESTAMPTZ,
    sealed_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chain_blocks_sequence_key UNIQUE (sequence_number),
    CONSTRAINT chain_blocks_hash_key UNIQUE (block_hash),
    CONSTRAINT chain_blocks_hash_lengths CHECK (
        octet_length(prev_hash) = 32
        AND octet_length(merkle_root) = 32
        AND octet_length(block_hash) = 32
    ),
    CONSTRAINT chain_blocks_non_empty CHECK (event_count > 0)
);

COMMENT ON TABLE ledger.chain_blocks IS
    'Append-only chain of Merkle-rooted blocks sealing ledger.event_digests.';

-- ---------------------------------------------------------------------------
-- Domain-separated hashing (RFC 6962 style)
-- ---------------------------------------------------------------------------
-- Leaves, internal nodes and blocks are hashed under different prefixes. Without
-- separation an internal node's hash could be presented as a leaf, which is the
-- classic second-preimage attack on Merkle trees.

CREATE OR REPLACE FUNCTION ledger.leaf_hash(p_canonical TEXT)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT digest('\x00'::BYTEA || convert_to(p_canonical, 'UTF8'), 'sha256');
$$;

CREATE OR REPLACE FUNCTION ledger.node_hash(p_left BYTEA, p_right BYTEA)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT digest('\x01'::BYTEA || p_left || p_right, 'sha256');
$$;

CREATE OR REPLACE FUNCTION ledger.merkle_root(p_leaves BYTEA[])
RETURNS BYTEA
LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE
AS $$
DECLARE
    level BYTEA[] := p_leaves;
    next_level BYTEA[];
    i INTEGER;
    n INTEGER;
BEGIN
    n := COALESCE(array_length(level, 1), 0);
    IF n = 0 THEN
        -- Empty tree: hash of nothing, under the leaf prefix.
        RETURN digest('\x00'::BYTEA, 'sha256');
    END IF;

    WHILE n > 1 LOOP
        next_level := ARRAY[]::BYTEA[];
        i := 1;
        WHILE i <= n LOOP
            IF i + 1 <= n THEN
                next_level := next_level || ledger.node_hash(level[i], level[i + 1]);
            ELSE
                -- Odd node is promoted UNCHANGED, never duplicated. Duplicating
                -- it (the Bitcoin approach) lets two different leaf sets produce
                -- the same root -- CVE-2012-2459.
                next_level := next_level || level[i];
            END IF;
            i := i + 2;
        END LOOP;
        level := next_level;
        n := COALESCE(array_length(level, 1), 0);
    END LOOP;

    RETURN level[1];
END;
$$;

CREATE OR REPLACE FUNCTION ledger.block_hash(
    p_prev_hash BYTEA, p_merkle_root BYTEA, p_sequence BIGINT, p_event_count INTEGER
) RETURNS BYTEA
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT digest(
        '\x02'::BYTEA || p_prev_hash || p_merkle_root
        || convert_to(p_sequence::TEXT || ':' || p_event_count::TEXT, 'UTF8'),
        'sha256'
    );
$$;

-- The chain's anchor. A fixed, well-known value so block 0's prev_hash is not
-- a secret and the whole chain is verifiable from scratch.
CREATE OR REPLACE FUNCTION ledger.genesis_hash()
RETURNS BYTEA
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT digest(convert_to('forensics-ledger-genesis-v1', 'UTF8'), 'sha256');
$$;

-- ---------------------------------------------------------------------------
-- Canonical form of an event row
-- ---------------------------------------------------------------------------
-- Field order is part of the protocol: changing it invalidates every existing
-- digest. It is duplicated in forensics.ledger.chain (Python), and a test
-- asserts the two implementations agree byte for byte.

CREATE OR REPLACE FUNCTION ledger.canonical_event(e evidence.events)
RETURNS TEXT
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT concat_ws('|',
        ledger.encode_field(e.event_id::TEXT),
        ledger.encode_timestamp(e.occurred_at),
        ledger.encode_timestamp(e.ingested_at),
        ledger.encode_field(e.category::TEXT),
        ledger.encode_field(e.action),
        ledger.encode_field(e.outcome::TEXT),
        ledger.encode_field(e.severity::TEXT),
        ledger.encode_field(e.message),
        ledger.encode_field(e.host_id::TEXT),
        ledger.encode_field(e.user_id::TEXT),
        ledger.encode_field(e.dataset_id::TEXT),
        ledger.encode_field(e.process_image_id::TEXT),
        ledger.encode_field(e.process_pid::TEXT),
        ledger.encode_field(e.process_command_line),
        ledger.encode_field(e.process_parent_image_id::TEXT),
        ledger.encode_field(e.process_parent_pid::TEXT),
        ledger.encode_field(e.source_address_id::TEXT),
        ledger.encode_field(e.source_port::TEXT),
        ledger.encode_field(e.destination_address_id::TEXT),
        ledger.encode_field(e.destination_port::TEXT),
        ledger.encode_field(e.protocol),
        ledger.encode_field(e.transport),
        ledger.encode_field(e.bytes_sent::TEXT),
        ledger.encode_field(e.bytes_received::TEXT),
        ledger.encode_field(e.direction::TEXT),
        ledger.encode_field(e.schema_version),
        ledger.encode_field(e.kafka_partition::TEXT),
        ledger.encode_field(e.kafka_offset::TEXT)
    );
$$;

CREATE OR REPLACE FUNCTION ledger.event_digest(e evidence.events)
RETURNS BYTEA
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $$
    SELECT ledger.leaf_hash(ledger.canonical_event(e));
$$;

-- ---------------------------------------------------------------------------
-- Digest-on-insert trigger
-- ---------------------------------------------------------------------------
-- Statement-level with a transition table, not per-row: the bulk path inserts
-- thousands of rows per statement, and a per-row plpgsql trigger on that is the
-- difference between a set-based INSERT and a loop.

CREATE OR REPLACE FUNCTION ledger.digest_inserted_events()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO ledger.event_digests (event_id, occurred_at, digest)
    SELECT n.event_id, n.occurred_at, ledger.event_digest(n.*)
    FROM new_events n
    -- An idempotent re-insert of an already-stored event must not disturb the
    -- digest that is already sealed into a block.
    ON CONFLICT (event_id, occurred_at) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE OR REPLACE TRIGGER evidence_events_digest
    AFTER INSERT ON evidence.events
    REFERENCING NEW TABLE AS new_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION ledger.digest_inserted_events();

-- ---------------------------------------------------------------------------
-- Sealing
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ledger.seal_block(p_max_events INTEGER DEFAULT 10000)
RETURNS TABLE (block_id BIGINT, sequence_number BIGINT, event_count INTEGER, block_hash BYTEA)
LANGUAGE plpgsql
AS $$
DECLARE
    v_leaves      BYTEA[];
    v_ids         UUID[];
    v_times       TIMESTAMPTZ[];
    v_prev        BYTEA;
    v_sequence    BIGINT;
    v_root        BYTEA;
    v_hash        BYTEA;
    v_count       INTEGER;
    v_block_id    BIGINT;
BEGIN
    -- Only one sealer at a time: two concurrent sealers would both read the
    -- same head and produce a fork. An advisory lock is the cheap way to say
    -- "this operation is single-writer" without blocking ingestion.
    PERFORM pg_advisory_xact_lock(hashtext('ledger.seal_block'));

    SELECT array_agg(d.digest ORDER BY d.digested_at, d.event_id),
           array_agg(d.event_id ORDER BY d.digested_at, d.event_id),
           array_agg(d.occurred_at ORDER BY d.digested_at, d.event_id),
           count(*)
      INTO v_leaves, v_ids, v_times, v_count
      FROM (
          -- Every reference is table-qualified: the RETURNS TABLE columns
          -- (block_id, event_count, ...) are plpgsql variables in this scope and
          -- would otherwise shadow the real columns of the same name.
          SELECT ed.* FROM ledger.event_digests ed
          WHERE ed.block_id IS NULL
          ORDER BY ed.digested_at, ed.event_id
          LIMIT p_max_events
      ) d;

    IF COALESCE(v_count, 0) = 0 THEN
        RETURN;   -- nothing to seal
    END IF;

    SELECT cb.block_hash, cb.sequence_number + 1
      INTO v_prev, v_sequence
      FROM ledger.chain_blocks cb
     ORDER BY cb.sequence_number DESC
     LIMIT 1;

    IF v_prev IS NULL THEN
        v_prev := ledger.genesis_hash();
        v_sequence := 0;
    END IF;

    v_root := ledger.merkle_root(v_leaves);
    v_hash := ledger.block_hash(v_prev, v_root, v_sequence, v_count);

    INSERT INTO ledger.chain_blocks
        (sequence_number, prev_hash, merkle_root, block_hash, event_count,
         first_event_at, last_event_at)
    VALUES (
        v_sequence, v_prev, v_root, v_hash, v_count,
        (SELECT min(t) FROM unnest(v_times) t),
        (SELECT max(t) FROM unnest(v_times) t)
    )
    RETURNING chain_blocks.block_id INTO v_block_id;

    UPDATE ledger.event_digests d
       SET block_id = v_block_id
      FROM unnest(v_ids, v_times) AS s(event_id, occurred_at)
     WHERE d.event_id = s.event_id AND d.occurred_at = s.occurred_at;

    block_id := v_block_id;
    sequence_number := v_sequence;
    event_count := v_count;
    block_hash := v_hash;
    RETURN NEXT;
END;
$$;

COMMENT ON FUNCTION ledger.seal_block(INTEGER) IS
    'Seal unsealed digests into the next chained block. Single-writer via advisory lock.';

CREATE OR REPLACE FUNCTION ledger.unsealed_events()
RETURNS BIGINT
LANGUAGE sql STABLE
AS $$
    SELECT count(*) FROM ledger.event_digests WHERE block_id IS NULL;
$$;

COMMENT ON FUNCTION ledger.unsealed_events() IS
    'Events digested but not yet sealed — the window in which a coordinated edit would go undetected.';

-- ---------------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------------
-- Returns one row per finding, empty when the ledger is intact. Returning
-- findings rather than raising means a single tampered row does not hide the
-- rest of the report — an investigator needs the whole picture, not the first
-- error.

CREATE OR REPLACE FUNCTION ledger.verify_events(p_limit INTEGER DEFAULT NULL)
RETURNS TABLE (finding TEXT, event_id UUID, occurred_at TIMESTAMPTZ, detail TEXT)
LANGUAGE plpgsql STABLE
AS $$
BEGIN
    -- Layer 1: does each event still hash to its stored digest?
    RETURN QUERY
    SELECT 'event_modified'::TEXT, e.event_id, e.occurred_at,
           'recomputed digest does not match ledger.event_digests'::TEXT
      FROM evidence.events e
      JOIN ledger.event_digests d
        ON d.event_id = e.event_id AND d.occurred_at = e.occurred_at
     WHERE ledger.event_digest(e.*) <> d.digest
     LIMIT COALESCE(p_limit, 1000000);

    -- An event with no digest at all: either the trigger was bypassed (someone
    -- with DDL rights disabled it) or the digest row was deleted.
    RETURN QUERY
    SELECT 'event_undigested'::TEXT, e.event_id, e.occurred_at,
           'event has no row in ledger.event_digests'::TEXT
      FROM evidence.events e
      LEFT JOIN ledger.event_digests d
        ON d.event_id = e.event_id AND d.occurred_at = e.occurred_at
     WHERE d.event_id IS NULL
     LIMIT COALESCE(p_limit, 1000000);

    -- A digest whose event is gone: deletion leaves this orphan behind, which
    -- is precisely how a removed record announces itself.
    RETURN QUERY
    SELECT 'event_deleted'::TEXT, d.event_id, d.occurred_at,
           'digest exists but the event row is missing'::TEXT
      FROM ledger.event_digests d
      LEFT JOIN evidence.events e
        ON e.event_id = d.event_id AND e.occurred_at = d.occurred_at
     WHERE e.event_id IS NULL
     LIMIT COALESCE(p_limit, 1000000);
END;
$$;

CREATE OR REPLACE FUNCTION ledger.verify_chain()
RETURNS TABLE (finding TEXT, sequence_number BIGINT, detail TEXT)
LANGUAGE plpgsql STABLE
AS $$
DECLARE
    r             RECORD;
    v_expected    BYTEA := ledger.genesis_hash();
    v_expected_seq BIGINT := 0;
    v_leaves      BYTEA[];
    v_root        BYTEA;
    v_hash        BYTEA;
    v_count       INTEGER;
BEGIN
    FOR r IN SELECT * FROM ledger.chain_blocks ORDER BY sequence_number LOOP
        -- Layer 3a: dense sequence. A gap means a block was removed.
        IF r.sequence_number <> v_expected_seq THEN
            finding := 'sequence_gap';
            sequence_number := r.sequence_number;
            detail := format('expected sequence %s', v_expected_seq);
            RETURN NEXT;
            v_expected_seq := r.sequence_number;
        END IF;

        -- Layer 3b: linkage. Every block must name its predecessor's hash.
        IF r.prev_hash <> v_expected THEN
            finding := 'broken_link';
            sequence_number := r.sequence_number;
            detail := format('prev_hash %s does not match previous block hash %s',
                             encode(r.prev_hash, 'hex'), encode(v_expected, 'hex'));
            RETURN NEXT;
        END IF;

        -- Layer 2: does the Merkle root still cover exactly these digests?
        SELECT array_agg(d.digest ORDER BY d.digested_at, d.event_id), count(*)
          INTO v_leaves, v_count
          FROM ledger.event_digests d
         WHERE d.block_id = r.block_id;

        IF COALESCE(v_count, 0) <> r.event_count THEN
            finding := 'event_count_mismatch';
            sequence_number := r.sequence_number;
            detail := format('block claims %s events, %s digests reference it',
                             r.event_count, COALESCE(v_count, 0));
            RETURN NEXT;
        END IF;

        IF v_leaves IS NOT NULL THEN
            v_root := ledger.merkle_root(v_leaves);
            IF v_root <> r.merkle_root THEN
                finding := 'merkle_root_mismatch';
                sequence_number := r.sequence_number;
                detail := format('recomputed root %s, stored %s',
                                 encode(v_root, 'hex'), encode(r.merkle_root, 'hex'));
                RETURN NEXT;
            END IF;
        END IF;

        -- Layer 3c: the block's own hash must cover its contents.
        v_hash := ledger.block_hash(r.prev_hash, r.merkle_root,
                                    r.sequence_number, r.event_count);
        IF v_hash <> r.block_hash THEN
            finding := 'block_hash_mismatch';
            sequence_number := r.sequence_number;
            detail := format('recomputed %s, stored %s',
                             encode(v_hash, 'hex'), encode(r.block_hash, 'hex'));
            RETURN NEXT;
        END IF;

        v_expected := r.block_hash;
        v_expected_seq := r.sequence_number + 1;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION ledger.verify_chain() IS
    'Walk the chain, recomputing Merkle roots and block hashes. Returns findings; empty means intact.';

-- ---------------------------------------------------------------------------
-- Inclusion proofs
-- ---------------------------------------------------------------------------
-- The reason for a Merkle tree rather than a flat hash of the block: a single
-- event can be proved to belong to a sealed block by disclosing O(log n) sibling
-- hashes — without revealing any other event in it. That matters when evidence
-- is handed to a third party who is entitled to one record and not the rest.

CREATE OR REPLACE FUNCTION ledger.inclusion_proof(p_event_id UUID, p_occurred_at TIMESTAMPTZ)
-- `position` is a reserved word in SQL (position(x IN y)).
RETURNS TABLE (tree_level INTEGER, sibling BYTEA, sibling_is_left BOOLEAN)
LANGUAGE plpgsql STABLE
AS $$
DECLARE
    v_block_id BIGINT;
    v_leaves   BYTEA[];
    v_index    INTEGER;
    v_level    BYTEA[];
    v_next     BYTEA[];
    n          INTEGER;
    i          INTEGER;
    depth      INTEGER := 0;
BEGIN
    SELECT d.block_id INTO v_block_id
      FROM ledger.event_digests d
     WHERE d.event_id = p_event_id AND d.occurred_at = p_occurred_at;

    IF v_block_id IS NULL THEN
        RETURN;   -- unsealed or unknown: no proof exists yet
    END IF;

    SELECT array_agg(d.digest ORDER BY d.digested_at, d.event_id)
      INTO v_leaves
      FROM ledger.event_digests d
     WHERE d.block_id = v_block_id;

    -- The window MUST carry its own ORDER BY. `row_number() OVER ()` numbers
    -- rows in arbitrary scan order and the outer ORDER BY is applied
    -- afterwards, so the index would not match the leaf's position in the
    -- array above -- and the proof would be built for the wrong path.
    SELECT idx INTO v_index
      FROM (
        SELECT row_number() OVER (ORDER BY d.digested_at, d.event_id) AS idx,
               d.event_id
          FROM ledger.event_digests d
         WHERE d.block_id = v_block_id
      ) ordered
     WHERE ordered.event_id = p_event_id;

    v_level := v_leaves;
    n := COALESCE(array_length(v_level, 1), 0);

    WHILE n > 1 LOOP
        -- Sibling of the current index at this level, if it has one.
        IF v_index % 2 = 1 THEN
            IF v_index + 1 <= n THEN
                tree_level := depth;
                sibling := v_level[v_index + 1];
                sibling_is_left := FALSE;
                RETURN NEXT;
            END IF;
        ELSE
            tree_level := depth;
            sibling := v_level[v_index - 1];
            sibling_is_left := TRUE;
            RETURN NEXT;
        END IF;

        v_next := ARRAY[]::BYTEA[];
        i := 1;
        WHILE i <= n LOOP
            IF i + 1 <= n THEN
                v_next := v_next || ledger.node_hash(v_level[i], v_level[i + 1]);
            ELSE
                v_next := v_next || v_level[i];
            END IF;
            i := i + 2;
        END LOOP;

        v_index := (v_index + 1) / 2;
        v_level := v_next;
        n := COALESCE(array_length(v_level, 1), 0);
        depth := depth + 1;
    END LOOP;
END;
$$;

-- ---------------------------------------------------------------------------
-- Operator view
-- ---------------------------------------------------------------------------

CREATE OR REPLACE VIEW ledger.chain_status AS
SELECT
    (SELECT count(*) FROM ledger.chain_blocks)                     AS blocks,
    (SELECT count(*) FROM ledger.event_digests)                    AS digested_events,
    (SELECT count(*) FROM ledger.event_digests WHERE block_id IS NULL) AS unsealed_events,
    (SELECT max(sequence_number) FROM ledger.chain_blocks)         AS head_sequence,
    (SELECT encode(block_hash, 'hex') FROM ledger.chain_blocks
      ORDER BY sequence_number DESC LIMIT 1)                       AS head_hash,
    (SELECT max(sealed_at) FROM ledger.chain_blocks)               AS last_sealed_at;

COMMENT ON VIEW ledger.chain_status IS
    'One-row summary of the ledger head, for monitoring and for `make ledger-status`.';

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- The application may read the ledger and append to it, and nothing else. No
-- UPDATE and no DELETE: a chain the writer can rewrite is not tamper-evident.
-- Blocks are written by the sealing function, which runs as the owner.

GRANT SELECT, INSERT ON ledger.event_digests TO forensics_app;
GRANT SELECT ON ledger.chain_blocks TO forensics_app;
GRANT SELECT ON ledger.chain_status TO forensics_app;
GRANT EXECUTE ON FUNCTION ledger.seal_block(INTEGER) TO forensics_app;
GRANT EXECUTE ON FUNCTION ledger.verify_chain() TO forensics_app;
GRANT EXECUTE ON FUNCTION ledger.verify_events(INTEGER) TO forensics_app;
GRANT EXECUTE ON FUNCTION ledger.unsealed_events() TO forensics_app;
GRANT EXECUTE ON FUNCTION ledger.inclusion_proof(UUID, TIMESTAMPTZ) TO forensics_app;
