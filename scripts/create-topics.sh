#!/usr/bin/env bash
#
# Idempotent topic provisioning. Runs as a one-shot Compose service after the
# broker reports healthy, and exits 0 so dependents gated on
# `service_completed_successfully` can start.
#
# Topics are created explicitly (auto-creation is disabled on the broker) so
# partition counts and retention are deliberate rather than inherited defaults.

set -euo pipefail

BOOTSTRAP="${KAFKA_BOOTSTRAP:-kafka:9092}"
PARTITIONS="${TOPIC_PARTITIONS:-6}"
RETENTION_MS="${TOPIC_RETENTION_MS:-604800000}"   # 7 days
REPLICATION=1                                     # single-node local cluster

KAFKA_TOPICS=/opt/kafka/bin/kafka-topics.sh

log() { printf '{"level":"INFO","service":"kafka-init","message":"%s"}\n' "$1"; }

# Belt-and-braces: the healthcheck already gated us, but a broker can still be
# mid-election when the dependent starts.
log "waiting for broker at ${BOOTSTRAP}"
for attempt in $(seq 1 30); do
  if "${KAFKA_TOPICS}" --bootstrap-server "${BOOTSTRAP}" --list >/dev/null 2>&1; then
    log "broker is reachable"
    break
  fi
  if [ "${attempt}" -eq 30 ]; then
    echo "kafka-init: broker unreachable after 30 attempts" >&2
    exit 1
  fi
  sleep 2
done

# create_topic <name> <partitions> <retention_ms> [extra --config args...]
create_topic() {
  local name="$1" partitions="$2" retention="$3"
  shift 3

  # --if-not-exists makes reruns safe, so `docker compose up` is repeatable.
  "${KAFKA_TOPICS}" \
    --bootstrap-server "${BOOTSTRAP}" \
    --create --if-not-exists \
    --topic "${name}" \
    --partitions "${partitions}" \
    --replication-factor "${REPLICATION}" \
    --config "retention.ms=${retention}" \
    --config "compression.type=producer" \
    "$@"

  log "topic ready: ${name} (partitions=${partitions}, retention.ms=${retention})"
}

# Raw ingest. Partition count sets the ceiling on Spark read parallelism, so it
# is sized above the current consumer count deliberately.
create_topic "${TOPIC_RAW:-logs.raw}" "${PARTITIONS}" "${RETENTION_MS}"

# Parsed/enriched events emitted by the Phase 2 Spark job.
create_topic "${TOPIC_NORMALIZED:-logs.normalized}" "${PARTITIONS}" "${RETENTION_MS}"

# Consumer-side dead letters: records that are deliverable but unparseable.
# Retained longer than the raw feed — a poison message must outlive the window
# in which someone might notice it.
create_topic "${TOPIC_DLQ:-logs.raw.dlq}" 3 2592000000   # 30 days

# Scored anomalies for alerting/evidence. Compacted retention is deliberate:
# alerts are evidence and must not silently age out mid-investigation.
create_topic "${TOPIC_ALERTS:-alerts.anomalies}" 3 2592000000

# Windowed feature streams produced by the Spark job. Fewer partitions than
# the raw feed: one row per (host, window) is far lower volume than raw events.
create_topic "${TOPIC_FEATURES_HOST:-features.host_activity}" 3 "${RETENTION_MS}"
create_topic "${TOPIC_FEATURES_PEER:-features.peer_connections}" 3 "${RETENTION_MS}"

log "listing topics"
"${KAFKA_TOPICS}" --bootstrap-server "${BOOTSTRAP}" --list

log "topic provisioning complete"
