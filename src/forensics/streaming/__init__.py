"""Stream-processing tier (Phase 2).

Spark Structured Streaming jobs that read ``logs.raw``, flatten and validate the
ECS payload, enrich it, and write to ``logs.normalized``. Records that fail
validation are routed to the ``logs.raw.dlq`` topic with the failure reason in a
header — see ``forensics.common.kafka`` for why consumer-side dead letters go to
a topic while producer-side ones go to a disk spool.

Anything read from ``labels.ground_truth`` must be dropped here before feature
extraction; it is evaluation data, not input.
"""
