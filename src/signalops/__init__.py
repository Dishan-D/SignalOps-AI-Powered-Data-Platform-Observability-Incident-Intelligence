"""SignalOps — operational intelligence for the forensics streaming pipeline.

Layering (each layer imports only the ones below it):

    api / dashboard / slack          presentation; no queries of their own
    investigation                    LLM agent over a fixed, read-only tool set
    services                         the operational queries and derivations
    sources                          Postgres / Kafka / runbook access

Nothing in this package is on the ingestion path. The streaming tier, the
detector and the sealer run identically whether or not SignalOps is deployed.
"""

__version__ = "0.1.0"
