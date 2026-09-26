"""Stateful windowed feature extraction.

Two feature streams, because the detections they serve have different natural
grains:

* :func:`host_activity_features` — per (window, host). Volume, failure ratios,
  privilege and fan-out signals. Catches brute force and privilege escalation.
* :func:`peer_connection_features` — per (window, host, destination_ip).
  Periodicity and payload uniformity. Catches C2 beaconing, which is invisible
  at host grain because the whole point of a beacon is to be low-volume.

**Ground-truth columns are never inputs.** The producer tags synthetic attacks
under ``eval_*`` so Phase 3 can measure precision and recall. Feeding those into
a feature would let the model read the answer off its own input, so
:data:`EXCLUDED_FROM_FEATURES` is asserted against the output of both functions
by ``tests/spark/test_features.py``.

All aggregation is watermarked. Without a watermark, Spark must retain state for
every window forever, and a long-running job dies of state-store growth rather
than of anything interesting.
"""

from __future__ import annotations

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

#: Columns that must never appear in, or contribute to, a feature vector.
EXCLUDED_FROM_FEATURES = (
    "eval_is_anomaly",
    "eval_scenario",
    "eval_campaign_id",
    "eval_step",
)

#: Command-line fragments an analyst would flag on sight. A crude
#: signature-based feature — deliberately so: it gives the Phase 3 model a
#: strong, cheap prior, and its failure mode (novel tradecraft it has never
#: seen) is exactly what the learned sequence model is there to cover.
SUSPICIOUS_COMMAND_PATTERNS = (
    "/dev/tcp/",
    "nc -e",
    "bash -i",
    "| bash",
    "|bash",
    "base64 -d",
    "chmod +s",
    "/etc/shadow",
)


def _interval_stats(epoch_list: Column) -> tuple[Column, Column, Column]:
    """Mean, stddev and count of gaps between sorted event times.

    Implemented with higher-order SQL functions (``array_sort``/``zip_with``/
    ``aggregate``) rather than a Python UDF. A UDF would serialise every window
    into the Python worker and back; these run in the JVM on the codegen path.

    A beacon's signature is a *small* interval stddev — a human-driven session
    is irregular, a scheduled callback is not.
    """
    sorted_epochs = F.array_sort(epoch_list)
    n = F.size(sorted_epochs)

    # gaps[i] = sorted[i+1] - sorted[i]
    gaps = F.zip_with(
        F.slice(sorted_epochs, 2, F.greatest(n - 1, F.lit(0))),
        F.slice(sorted_epochs, 1, F.greatest(n - 1, F.lit(0))),
        lambda later, earlier: (later - earlier).cast("double"),
    )
    gap_count = F.size(gaps)

    total = F.aggregate(gaps, F.lit(0.0), lambda acc, x: acc + x)
    # Fewer than two gaps makes a standard deviation meaningless, not zero —
    # returning 0.0 there would fabricate a perfect beacon out of two events.
    mean_gap = F.when(gap_count > 0, total / gap_count)

    sum_sq_dev = F.aggregate(
        gaps, F.lit(0.0), lambda acc, x: acc + F.pow(x - mean_gap, F.lit(2.0))
    )
    stddev_gap = F.when(gap_count > 1, F.sqrt(sum_sq_dev / gap_count))

    return mean_gap, stddev_gap, gap_count


def _interval_struct(epoch_list: Column) -> Column:
    """Package :func:`_interval_stats` into one struct so it is built once."""
    mean_gap, stddev_gap, gap_count = _interval_stats(epoch_list)
    return F.struct(
        mean_gap.alias("mean_seconds"),
        stddev_gap.alias("stddev_seconds"),
        gap_count.alias("sample_count"),
    )


def _is_suspicious_command() -> Column:
    """1 when the command line matches any known tradecraft fragment."""
    lowered = F.lower(F.coalesce(F.col("process_command_line"), F.lit("")))
    match = F.lit(False)
    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        match = match | lowered.contains(pattern)
    return F.when(match, F.lit(1)).otherwise(F.lit(0))


def host_activity_features(
    df: DataFrame,
    *,
    watermark_delay: str = "2 minutes",
    window_duration: str = "1 minute",
    window_slide: str = "30 seconds",
) -> DataFrame:
    """Per-host windowed activity features.

    Sliding rather than tumbling windows: a burst straddling a tumbling
    boundary is split in half and can fall under threshold on both sides.
    """
    return (
        df.withWatermark("event_time", watermark_delay)
        .groupBy(
            F.window(F.col("event_time"), window_duration, window_slide).alias("window"),
            F.col("host_name"),
        )
        .agg(
            F.count(F.lit(1)).alias("event_count"),
            # --- authentication pressure (brute force) -----------------------
            F.sum(
                F.when(
                    (F.col("category") == "authentication")
                    & (F.col("outcome") == "failure"),
                    1,
                ).otherwise(0)
            ).alias("auth_failure_count"),
            F.sum(
                F.when(
                    (F.col("category") == "authentication")
                    & (F.col("outcome") == "success"),
                    1,
                ).otherwise(0)
            ).alias("auth_success_count"),
            # Fan-in of distinct sources: one IP hammering one host looks very
            # different from many users logging in normally.
            F.approx_count_distinct(F.col("source_ip")).alias("distinct_source_ips"),
            F.approx_count_distinct(F.col("user_name")).alias("distinct_users"),
            # --- process behaviour (execution, escalation) -------------------
            F.sum(
                F.when(F.col("category") == "process", 1).otherwise(0)
            ).alias("process_event_count"),
            F.approx_count_distinct(F.col("process_name")).alias("distinct_processes"),
            F.sum(_is_suspicious_command()).alias("suspicious_command_count"),
            # uid 0 activity is rare in the baseline and central to escalation.
            F.sum(F.when(F.col("user_uid") == 0, 1).otherwise(0)).alias("root_event_count"),
            # --- network volume (exfiltration) -------------------------------
            F.coalesce(F.sum(F.col("bytes_sent")), F.lit(0)).cast("long").alias("bytes_sent_total"),
            F.coalesce(F.max(F.col("bytes_sent")), F.lit(0)).cast("long").alias("bytes_sent_max"),
            F.approx_count_distinct(F.col("destination_ip")).alias("distinct_destinations"),
            F.sum(
                F.when(F.col("direction") == "outbound", 1).otherwise(0)
            ).alias("outbound_flow_count"),
            # --- severity ----------------------------------------------------
            # Severity is syslog-style, so *lower* is more urgent.
            F.min(F.col("severity")).alias("min_severity"),
        )
        .withColumn("window_start", F.col("window")["start"])
        .withColumn("window_end", F.col("window")["end"])
        .withColumn(
            # Ratio, not raw count: 20 failures out of 20 attempts is an attack,
            # 20 out of 5000 is a Monday morning.
            "auth_failure_ratio",
            F.when(
                (F.col("auth_failure_count") + F.col("auth_success_count")) > 0,
                F.col("auth_failure_count")
                / (F.col("auth_failure_count") + F.col("auth_success_count")),
            ).otherwise(F.lit(0.0)),
        )
        .drop("window")
    )


def peer_connection_features(
    df: DataFrame,
    *,
    watermark_delay: str = "2 minutes",
    window_duration: str = "10 minutes",
    window_slide: str = "5 minutes",
) -> DataFrame:
    """Per (host, destination) features targeting periodic C2 traffic.

    The window is much longer than the host-activity window on purpose: a beacon
    on a 300-second interval produces two samples in ten minutes and none at all
    in one, so a short window cannot see periodicity by construction.
    """
    return (
        df.filter(F.col("destination_ip").isNotNull())
        .withWatermark("event_time", watermark_delay)
        .groupBy(
            F.window(F.col("event_time"), window_duration, window_slide).alias("window"),
            F.col("host_name"),
            F.col("destination_ip"),
        )
        .agg(
            F.count(F.lit(1)).alias("connection_count"),
            F.collect_list(F.col("event_time").cast("long")).alias("_epochs"),
            F.avg(F.col("bytes_sent").cast("double")).alias("bytes_sent_mean"),
            # Near-zero payload variance across many connections is the other
            # half of the beacon signature: machines send identical check-ins.
            F.stddev_samp(F.col("bytes_sent").cast("double")).alias("bytes_sent_stddev"),
            F.coalesce(F.sum(F.col("bytes_sent")), F.lit(0)).cast("long").alias("bytes_sent_total"),
            F.approx_count_distinct(F.col("destination_port")).alias("distinct_ports"),
            F.min(F.col("destination_port")).alias("destination_port"),
        )
        .withColumn("window_start", F.col("window")["start"])
        .withColumn("window_end", F.col("window")["end"])
        # Built once into a struct rather than calling _interval_stats per
        # column: each call rebuilds the whole array expression tree.
        .withColumn("_interval", _interval_struct(F.col("_epochs")))
        .withColumn("interval_mean_seconds", F.col("_interval")["mean_seconds"])
        .withColumn("interval_stddev_seconds", F.col("_interval")["stddev_seconds"])
        .withColumn("interval_sample_count", F.col("_interval")["sample_count"])
        .withColumn(
            # Coefficient of variation: scale-free, so a 30 s beacon and a 300 s
            # beacon score the same. Near 0 == metronomic.
            "interval_cv",
            F.when(
                F.col("interval_mean_seconds") > 0,
                F.col("interval_stddev_seconds") / F.col("interval_mean_seconds"),
            ),
        )
        .drop("window", "_epochs", "_interval")
    )


def assert_no_label_leakage(df: DataFrame) -> None:
    """Fail loudly if an evaluation label reached a feature frame.

    Cheap insurance against the single most damaging bug in an ML pipeline: a
    model that scores brilliantly offline because it was shown the answer.
    """
    leaked = sorted(set(df.columns) & set(EXCLUDED_FROM_FEATURES))
    if leaked:
        raise ValueError(
            f"Evaluation labels leaked into feature frame: {leaked}. "
            "These columns are ground truth and must never be features."
        )
