SignalOps — AI-Powered Data Platform Observability & Incident Intelligence

SignalOps is a real-time data platform for streaming telemetry, detecting anomalous activity, monitoring pipeline health, and assisting engineers with incident investigation. It combines distributed data processing, operational observability, machine-learning-based anomaly detection, and tamper-evident evidence storage in a single system.

The project is built around Apache Kafka, Apache Spark Structured Streaming, PostgreSQL, and a transformer-based log anomaly detector. The planned operational layer adds interactive dashboards, diagnostic APIs, and an LLM-powered investigation assistant that retrieves relevant runbooks and produces evidence-grounded incident summaries.

Implementation status: The underlying streaming, anomaly-detection, and evidence-ledger pipeline is implemented and verified end-to-end. The SignalOps observability dashboard, operational API, and AI investigation assistant are planned extensions and should be marked complete only after implementation and testing.

Key Capabilities

* Real-Time Data Processing: Ingests structured log telemetry through Kafka and processes it using Spark Structured Streaming.
* Pipeline Observability: Planned dashboards for ingestion throughput, processing latency, dead-letter queues, anomaly trends, and pipeline health.
* Anomaly Detection: Uses a LogBERT-style transformer trained on benign log sequences to detect anomalous activity.
* Incident Intelligence: Planned LLM-powered investigation workflow using structured tool calling and runbook retrieval.
* Operational APIs: Planned FastAPI endpoints for pipeline metrics, failures, detection details, and evidence-integrity status.
* Tamper-Evident Evidence: Uses SHA-256 digests, Merkle trees, and chained blocks to detect unauthorized evidence modifications.
* Fault-Tolerant Ingestion: Supports durable Kafka publishing, validation with dead-letter routing, and local spooling when the broker is unavailable.
* Reproducible Testing: Uses deterministic synthetic telemetry and automated tests across processing, model, and database components.

Architecture

                    Synthetic / External Telemetry
                               |
                               v
                    +----------------------+
                    |   Kafka (KRaft)      |
                    |      logs.raw        |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Spark Structured     |
                    | Streaming            |
                    | Parse / Validate /   |
                    | Normalize / Window   |
                    +----+------------+----+
                         |            |
             +-----------+            +----------------+
             |                                         |
             v                                         v
    +--------------------+                  +--------------------+
    | Normalized Events  |                  | Feature Streams    |
    | logs.normalized    |                  | Host / Peer        |
    +---------+----------+                  +---------+----------+
              |                                       |
              v                                       v
    +--------------------+                  +--------------------+
    | PostgreSQL         |                  | Anomaly Detector   |
    | Evidence &         |                  | Drain + LogBERT    |
    | Analytics          |                  +---------+----------+
    +---------+----------+                            |
              |                                       v
              v                             +--------------------+
    +--------------------+                  | Detection Results  |
    | SHA-256 Digests     |                  | & Anomaly Alerts   |
    | Merkle-Chained      |                  +---------+----------+
    | Evidence Ledger     |                            |
    +---------+----------+                             |
              |                                        |
              +------------------+---------------------+
                                 |
                                 v
                     +-------------------------+
                     | SignalOps Operations    |
                     | Layer (Planned)         |
                     |                         |
                     | Streamlit / Plotly      |
                     | FastAPI                 |
                     | LLM Investigation Agent |
                     | Runbook Retrieval       |
                     +-------------------------+

Technology Stack

Component	Technology	Purpose
Ingestion	Python, Apache Kafka 3.9	Reliable telemetry ingestion and event transport
Stream Processing	Apache Spark 4.0 Structured Streaming	Validation, normalization, windowed feature extraction
Data Storage	PostgreSQL 17	Normalized evidence, analytics, and detection results
Anomaly Detection	PyTorch, LogBERT-style transformer	Sequence-based anomaly scoring
Template Mining	Drain	Convert raw logs into structured log templates
Evidence Integrity	SHA-256, Merkle trees	Tamper detection and evidence verification
Operational API	FastAPI — planned	Programmatic access to pipeline health and incident data
Dashboard	Streamlit, Plotly — planned	Operational metrics and incident visualization
AI Investigation	LLM tool calling and runbook retrieval — planned	Evidence-grounded incident investigation
Infrastructure	Docker Compose	Reproducible multi-service environment
Quality	pytest, Ruff, mypy	Automated testing, linting, and type checking

1. Streaming Data Pipeline

The pipeline ingests Elastic Common Schema (ECS)-style telemetry and routes it through Kafka and Spark.

Processing workflow

1. Ingestion: A deterministic synthetic telemetry producer publishes events to Kafka.
2. Validation: Spark parses records against an explicit schema and identifies malformed or invalid events.
3. Normalization: Valid events are flattened and transformed into a relational evidence model.
4. Feature Extraction: Windowed host-activity and peer-connection features are generated for downstream detection.
5. Persistence: Events and analytics are stored in PostgreSQL.
6. Detection: The anomaly detector scores log sequences and publishes anomalous events.
7. Integrity Protection: Evidence records receive cryptographic digests and are sealed into Merkle-rooted blocks.

Invalid records are routed to logs.raw.dlq with their payloads preserved. This prevents a malformed event from terminating the entire streaming workload.

Kafka topics

Topic	Purpose
logs.raw	Incoming telemetry
logs.normalized	Validated and normalized events
logs.raw.dlq	Invalid records and validation failures
features.host_activity	Windowed host-level activity
features.peer_connections	Host-to-destination connection features
alerts.anomalies	Anomaly alerts

2. Data Platform Observability

Planned SignalOps capability

The observability layer will expose pipeline behavior through a dashboard backed by actual operational data rather than hardcoded demonstration metrics.

Planned dashboard metrics

* Event ingestion rate and processed-event counts
* Processing latency and ingestion-to-normalization discrepancies
* Dead-letter queue volume and validation failures
* Anomaly counts and detection trends
* Kafka, Spark, and PostgreSQL service health
* Evidence-ledger verification status and unsealed-event backlog

The dashboard will help engineers distinguish normal workload variation from operational failures and identify where a pipeline is experiencing delays.

Unavailable measurements will be identified explicitly rather than presented as healthy or zero-valued metrics.

3. AI-Assisted Incident Investigation

Planned SignalOps capability

The investigation assistant will combine operational telemetry, diagnostic APIs, and troubleshooting documentation to help engineers investigate incidents.

Investigation workflow

1. Retrieve current pipeline health and relevant metrics.
2. Identify recent processing failures, validation errors, or abnormal queue growth.
3. Retrieve the affected detection or host timeline when applicable.
4. Search relevant operational runbooks.
5. Generate an incident summary containing observed evidence, supporting findings, possible explanations, and recommended investigation steps.

Agent design principles

* Structured tool calling: Access operational information through defined tools rather than unrestricted database or shell access.
* Evidence-grounded responses: Base incident summaries on returned telemetry and diagnostic results.
* Runbook retrieval: Connect observed failures to relevant troubleshooting procedures.
* Explicit uncertainty: Distinguish confirmed observations from hypotheses.
* Read-only investigation: Prevent the agent from modifying evidence or executing arbitrary commands.
* Failure isolation: Keep ingestion, stream processing, and dashboard data access independent of LLM availability.

This design targets repetitive diagnostic work while preserving human oversight over incident response.

4. Operational API

Planned SignalOps capability

A FastAPI service will expose a read-only interface to operational information.

Proposed endpoints include:

Endpoint	Purpose
GET /api/ops/health	Service and pipeline health
GET /api/ops/metrics	Available operational metrics
GET /api/ops/incidents	Recent incidents and failures
GET /api/ops/dlq/summary	Dead-letter queue statistics
GET /api/ops/detections	Recent anomaly detections
GET /api/ops/hosts/{host_id}/timeline	Host activity for investigation
GET /api/ops/ledger/status	Evidence-ledger integrity status
POST /api/ops/investigate	Request an AI-assisted investigation

Endpoint contracts will be finalized against the existing database schema and actual telemetry sources during implementation.

5. Transformer-Based Anomaly Detection

The existing detection pipeline uses Drain template mining and a LogBERT-style transformer to identify anomalous log sequences.

Detection workflow

Raw Log Message
      |
      v
Drain Template Mining
      |
      v
Log-Key Sequence
      |
      v
Transformer-Based Scoring
      |
      v
Calibrated Thresholds
      |
      v
Anomaly Detection Results

The detector is trained on benign sequences, reflecting the practical difficulty of obtaining representative attack labels. Synthetic attack labels are reserved for evaluation and excluded from model features.

Reported evaluation results

Metric	LogBERT-style Detector	Unseen-Template Baseline
Precision	0.853	1.000
Recall	0.794	0.245
F1-score	0.833	0.393
PR-AUC	0.837	0.342

These measurements come from the project’s synthetic evaluation datasets. They demonstrate performance within the simulation and should not be interpreted as validated production-security performance.

6. Tamper-Evident Evidence Ledger

The evidence store protects event integrity using cryptographic digests and chained Merkle blocks.

Integrity workflow

1. Generate a SHA-256 digest for each evidence record.
2. Seal event digests into a Merkle tree.
3. Store the Merkle root in a chained block.
4. Link each block to the previous block using a cryptographic hash.
5. Verify evidence independently using a Python verifier.

The implementation detects event modification, coordinated event-and-digest modification after sealing, deleted events, missing digests, modified blocks, and broken block sequences.

Merkle inclusion proofs allow an individual event’s membership in a sealed block to be verified without disclosing every event in that block.

The ledger has an explicitly documented unsealed interval between event insertion and block sealing. The verification process reports unsealed events rather than treating them as already protected by a sealed block.

7. Reliability and Engineering Practices

The existing implementation incorporates several operational safeguards:

* Kafka publishing with acknowledgements and idempotence enabled.
* Explicit event schemas and validation-specific failure reasons.
* Dead-letter routing for invalid records.
* A local spool for records that cannot be delivered while Kafka is unavailable.
* Idempotent database ingestion to handle redelivered events.
* Checkpointed Spark processing.
* Non-root containers and least-privilege database permissions.
* Structured JSON logging with correlation identifiers.
* Reproducible synthetic data generation.
* Versioned database migrations with checksum validation.

The current deployment is single-node and uses a single Kafka broker. Horizontal scale-out has not been verified.

8. Testing

The existing repository includes tests across core functionality, model behavior, Spark processing, and PostgreSQL integration.

Suite	Coverage
Core	Event generation, configuration, schemas, ledger protocol
Model	Template mining, sequence construction, training, calibration, scoring
Spark	Validation, routing, windowing, checkpoint behavior
Database	Normalization, idempotency, indexing, evidence integrity

The repository documents approximately 270 tests, with Ruff and mypy checks. Exact counts should be confirmed against the current checkout before being quoted elsewhere.

The planned SignalOps layer will require additional tests covering dashboard metric calculations, API behavior, missing telemetry, agent tool execution, runbook retrieval, evidence grounding, service failures, and LLM unavailability.

9. Quick Start

Run the existing pipeline

git clone https://github.com/Dishan-D/Cyber-Forensics-Log-Anomaly-Pipeline-.git
cd Cyber-Forensics-Log-Anomaly-Pipeline-

Configure the environment:

cp .env.example .env

Set the required database credentials in .env, then start the existing services:

make up

Useful commands include:

make producer-logs
make spark-logs
make evidence
make ledger-status
make ledger-verify
make train
make detect
make alerts
make detection-quality

Run the existing checks:

make check
make test-model
make test-spark
make test-db

See the repository’s Makefile and configuration files for exact prerequisites and behavior.

The dashboard, operational API, and investigation assistant are not part of the verified existing pipeline described above. Their startup commands should be added here after those services have been implemented and integrated.

10. Roadmap

* Operational metrics API backed by existing pipeline data
* Interactive observability dashboard
* Incident and processing-failure views
* Read-only LLM investigation agent with structured tools
* Runbook indexing and retrieval
* Evidence-grounded incident summaries
* Integration tests for operational failure scenarios
* Optional Slack-based engineering self-service
* End-to-end demonstration of detecting and investigating a controlled pipeline failure

Limitations

* Anomaly-detection metrics are measured on synthetic datasets.
* The deployment uses a single Kafka broker and a single Spark driver.
* The producer’s local dead-letter spool does not yet have an automated replay job.
* Existing anomaly alerts are stored, but automated incident triage and notification are not implemented.
* Events remain unsealed for a bounded interval before ledger sealing.
* The SignalOps dashboard, operational API, and AI investigation workflow remain planned until implemented and verified.

Project Goal

SignalOps aims to bring streaming data engineering, operational observability, and AI-assisted incident investigation into one coherent platform.

The goal is to help engineers understand what a data pipeline is doing, identify where it is failing, retrieve relevant troubleshooting guidance, and investigate incidents using evidence from the underlying system.
