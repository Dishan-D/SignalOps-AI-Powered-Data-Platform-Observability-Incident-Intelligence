"""Detection tier (Phase 3).

Transformer-based log-sequence modelling (LogBERT). Consumes
``logs.normalized``, templatises each raw ``message`` into a log key, scores
per-host sequences, and publishes detections to ``alerts.anomalies``.

Ground-truth labels emitted by the synthetic producer are the evaluation set for
this tier and must never be used as features.
"""
