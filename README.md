SignalOps — AI-Powered Data Platform Observability & Incident Intelligence

SignalOps is a real-time data platform designed to help engineers monitor streaming pipelines, detect anomalous activity, investigate operational failures, and understand incidents using evidence from telemetry and troubleshooting documentation.

Built around Apache Kafka, Apache Spark Structured Streaming, and PostgreSQL, SignalOps ingests and transforms telemetry, extracts streaming features, detects anomalous behavior, and preserves forensic evidence through a tamper-evident ledger.

The planned operational layer extends this foundation with interactive dashboards, a REST API, an LLM-powered investigation agent, runbook retrieval, and Slack-based self-service workflows.

The goal is to reduce manual investigation effort by turning raw pipeline signals, errors, detections, and operational documentation into actionable engineering insights.

Implementation status: The streaming pipeline, anomaly detector, and evidence ledger are implemented and have been tested end-to-end. The observability dashboard, operational API, LLM investigation agent, runbook retrieval, and Slack integration are planned components until their implementation and tests are complete.

⸻

Table of Contents

* Overview
* Key Capabilities
* Architecture
* Technology Stack
* Data Pipeline
* Streaming Feature Engineering
* Anomaly Detection
* Tamper-Evident Evidence Ledger
* SignalOps Observability
* AI-Powered Incident Investigation
* Operational API
* Slack-Based Self-Service
* Reliability and Security
* Testing and Validation
* Getting Started
* Configuration
* Roadmap
* Limitations

⸻

Overview

Modern data platforms process high volumes of events across distributed services. When processing delays, malformed records, unusual activity, or downstream failures occur, engineers often need to inspect multiple data sources and correlate evidence manually.

SignalOps explores how streaming data infrastructure, anomaly detection, operational observability, and AI-assisted investigation can work together in a single system.

The platform has three main layers:

Layer	Responsibility
Streaming Data Platform	Ingest telemetry, normalize events, validate records, and extract streaming features.
Detection and Evidence	Identify anomalous activity and maintain tamper-evident forensic records.
Operational Intelligence	Expose pipeline metrics, visualize failures, retrieve runbooks, and assist engineers with incident investigation.

The first two layers form the implemented foundation. The operational intelligence layer is the next stage of development.

Design Principles

* Streaming-first: Process telemetry continuously rather than relying exclusively on periodic batch jobs.
* Evidence-grounded: Base detections and investigation summaries on available events, metrics, and documented evidence.
* Observable by design: Expose meaningful indicators of ingestion, processing, data quality, and downstream health.
* Failure isolation: Keep core ingestion and processing independent of optional LLM services.
* Reproducibility: Use containerized infrastructure and automated tests to validate behavior.
* Explicit uncertainty: Distinguish observed facts from hypotheses when investigating incidents.
* Incremental architecture: Add operational capabilities without replacing the existing streaming pipeline.

⸻

Key Capabilities

Implemented

* Synthetic enterprise telemetry generation.
* Kafka-based event ingestion using KRaft mode.
* Spark Structured Streaming for parsing, validation, normalization, and feature extraction.
* Dead-letter routing for records that cannot be processed normally.
* PostgreSQL persistence with a normalized evidence schema.
* Log-template processing and transformer-based anomaly detection.
* Tamper-evident evidence ledger using cryptographic hashes and Merkle-rooted blocks.
* Docker Compose-based environment for local execution.
* Automated tests for pipeline, model, database, and evidence-ledger components.

Planned

* Interactive operational dashboards using Streamlit and Plotly.
* FastAPI endpoints for pipeline health, metrics, detections, and ledger status.
* LLM-powered incident investigation with structured tool calling.
* Runbook retrieval for context-aware troubleshooting.
* Slack commands for engineering self-service.
* Integration tests covering the complete operational investigation workflow.

⸻

Architecture

High-Level Architecture

                   SYNTHETIC TELEMETRY
                           |
                           v
                  +------------------+
                  | Telemetry Producer|
                  +------------------+
                           |
                           v
                  +------------------+
                  |   Apache Kafka   |
                  |                  |
                  | logs.raw         |
                  | logs.normalized  |
                  | logs.raw.dlq     |
                  +------------------+
                           |
                           v
                  +------------------+
                  | Apache Spark     |
                  | Structured       |
                  | Streaming        |
                  +------------------+
                           |
                +----------+-----------+
                |                      |
                v                      v
       +------------------+   +--------------------+
       | PostgreSQL       |   | Feature Streams    |
       | Evidence Storage |   | Host / Peer Activity|
       +------------------+   +--------------------+
                |                      |
                |                      v
                |             +--------------------+
                |             | Anomaly Detector   |
                |             +--------------------+
                |                      |
                +----------+-----------+
                           |
                           v
                  +------------------+
                  | Evidence Ledger  |
                  | Hashes and       |
                  | Merkle Roots     |
                  +------------------+
                 PLANNED OPERATIONAL LAYER
                 -------------------------
         PostgreSQL / Kafka / Spark Signals
                           |
                           v
                  +------------------+
                  | SignalOps API    |
                  | FastAPI          |
                  +------------------+
                           |
             +-------------+--------------+
             |             |              |
             v             v              v
        Dashboard     Investigation    Slack
        Streamlit     Agent + LLM      Integration
        + Plotly      + Runbooks

The operational components shown in the lower section are planned and should be marked as implemented only after they have been built and tested.

Event Flow

1. A telemetry producer generates synthetic enterprise log events.
2. Kafka receives the raw events and distributes them to consumers.
3. Spark Structured Streaming parses, validates, and normalizes incoming records.
4. Invalid or unprocessable records are routed to a dead-letter topic.
5. Valid records are transformed into structured records and streaming features.
6. PostgreSQL stores the resulting evidence in a normalized schema.
7. The detection pipeline identifies anomalous activity using learned log representations and behavioral features.
8. Evidence is incorporated into the tamper-evident ledger.
9. The planned operational layer will expose these signals through dashboards, APIs, and investigation workflows.

⸻

Technology Stack

Component	Technology	Purpose
Language	Python 3.12	Pipeline, feature engineering, detection, and service development
Event Streaming	Apache Kafka 3.9	Distributed event ingestion and topic-based processing
Stream Processing	Apache Spark 4.0 Structured Streaming	Event transformation and streaming feature extraction
Database	PostgreSQL 17	Structured evidence and pipeline data persistence
Machine Learning	PyTorch	Transformer-based anomaly detection
Log Processing	Drain-style log template extraction	Convert variable log messages into structured templates
Containerization	Docker Compose	Local infrastructure orchestration
Testing	pytest	Automated unit and integration testing
Code Quality	Ruff, mypy	Linting and static type checking
Operational API	FastAPI — planned	Read-only operational endpoints and investigation tools
Dashboard	Streamlit, Plotly — planned	Pipeline metrics and interactive visualizations
AI Investigation	LLM with structured tool calling — planned	Evidence-grounded incident investigation
Documentation Retrieval	Runbook search — planned	Retrieve relevant troubleshooting procedures
Engineering Integration	Slack API — planned	Self-service operational commands

⸻

Data Pipeline

The streaming pipeline provides the foundation for SignalOps.

1. Telemetry Generation

A synthetic producer generates enterprise-style log events representing normal activity and selected attack scenarios.

Example scenarios include:

* SSH brute-force attempts.
* Reverse-shell activity.
* Command-and-control beaconing.
* Privilege escalation.
* Data exfiltration.

The data is synthetic and intended for development, testing, and reproducible evaluation.

2. Kafka Ingestion

Kafka provides the ingestion and distribution layer.

The documented topics are:

Topic	Purpose
logs.raw	Incoming telemetry events
logs.normalized	Normalized event stream
logs.raw.dlq	Raw records that cannot be processed normally
features.host_activity	Host-level behavioral features
features.peer_connections	Peer and connection-related features
alerts.anomalies	Anomaly alerts

3. Stream Processing

Spark Structured Streaming handles:

* Event parsing.
* Schema validation.
* Field normalization.
* Feature extraction.
* Routing of invalid records.
* Persistence of processed data.

This separates ingestion from downstream analytical processing and establishes a foundation for measuring processing health.

4. Persistence

PostgreSQL stores processed records and forensic evidence.

The data model uses a normalized relational structure to reduce unnecessary duplication and support consistent querying.

The planned operational layer will query this persisted information to calculate metrics and retrieve incident context.

5. Dead-Letter Handling

Records that fail validation or processing can be routed to a dead-letter topic for later inspection.

Dead-letter volume and representative failure reasons are useful operational signals because they can reveal schema drift, malformed input, and processing problems.

Current scope: The dead-letter routing path exists. Automated replay and recovery workflows remain future work.

⸻

Streaming Feature Engineering

SignalOps extracts structured information from telemetry to support downstream analysis.

The feature pipeline includes host-activity and peer-connection signals, which provide a more useful representation of behavior than unprocessed log messages alone.

Examples of potential operational indicators include:

* Events processed over a time window.
* Activity grouped by host.
* Repeated connection attempts.
* Changes in log-template frequency.
* Failed or invalid records.
* Unusual patterns in event sequences.

These indicators can support anomaly detection and, once implemented, operational dashboards and incident investigations.

The pipeline must distinguish measured signals from inferred explanations. For example, an increase in dead-letter records is an observation; attributing it to a schema change requires additional evidence.

⸻

Anomaly Detection

SignalOps includes a log-anomaly detection pipeline combining log-template extraction with a transformer-based model.

Detection Workflow

1. Convert variable log messages into structured templates using Drain-style processing.
2. Represent log sequences for model-based analysis.
3. Train the transformer-based detector on benign data.
4. Evaluate the model on held-out examples.
5. Emit anomaly results for downstream investigation.

The implementation uses a compact LogBERT-style transformer built with PyTorch.

Reported Evaluation

The existing project documentation reports the following results:

Metric	Reported Value
Precision	0.853
Recall	0.794
F1 Score	0.833
PR-AUC	0.837

For the documented unseen-template baseline:

Metric	Reported Value
Precision	1.000
Recall	0.245
F1 Score	0.393

The baseline illustrates a key trade-off: high precision does not necessarily imply adequate recall.

These results come from the project’s synthetic evaluation setup. They should not be interpreted as evidence of production performance or generalization to real enterprise telemetry.

Important Evaluation Considerations

* Keep labels out of model features to prevent data leakage.
* Separate training and evaluation data appropriately.
* Evaluate behavior on previously unseen log templates.
* Consider false positives and false negatives separately.
* Track model performance when the underlying log distribution changes.

⸻

Tamper-Evident Evidence Ledger

The evidence ledger provides a mechanism for detecting modifications to stored forensic records.

Design

The implemented approach combines:

* SHA-256 event digests.
* Sealed blocks of event hashes.
* Merkle roots for integrity verification.
* Chained block metadata.
* Inclusion proofs for verifying whether an event belongs to a sealed block.

This makes it possible to verify whether records covered by a seal remain consistent with the recorded cryptographic commitments.

Documented Integrity Checks

The implementation is designed to detect:

* Changes to an event after sealing.
* Changes to an event and its stored digest after sealing.
* Deletion of sealed events.
* Modifications to sealed blocks.
* Removal of sealed blocks.

Inclusion proofs provide a way to verify membership without requiring the verifier to trust the event’s surrounding application logic.

Limitations

The ledger provides tamper evidence, not an unconditional guarantee against every form of compromise.

In particular:

* Events can remain unsealed before the next sealing operation.
* Security depends on how sealing metadata and verification material are protected.
* A compromised system may affect data before it is sealed.
* Scale-out behavior and distributed failure scenarios require additional validation.

SignalOps should expose the sealing status and unsealed backlog as operational signals once the dashboard and API are implemented.

⸻

SignalOps Observability

Status: Planned

The observability layer will turn pipeline state and persisted evidence into actionable operational views.

Dashboard

The proposed dashboard uses Streamlit and Plotly to present pipeline health, throughput, processing behavior, data quality, and detection activity.

Planned panels include:

Panel	Information
Pipeline Health	Availability and health-check results for relevant components
Ingestion	Incoming event volume and throughput over time
Processing	Available Spark progress and processing indicators
Data Quality	Landing-versus-normalized record counts and validation failures
Dead-Letter Queue	DLQ volume and available failure details
Anomaly Activity	Detection counts and trends over time
Host Activity	Available host-level behavioral signals
Evidence Integrity	Ledger verification status and unsealed backlog

Only metrics that can be obtained reliably from the existing infrastructure should be displayed.

For example, if end-to-end processing latency is not currently measured, it should not be presented as a real metric until timestamps and measurement logic have been added.

Operational Metric Sources

Signal	Proposed Source
Ingestion volume	Kafka offsets, producer metrics, or available ingestion records
Processing progress	Spark Structured Streaming progress information
Normalization discrepancy	Comparison of appropriate landing and normalized record counts
Dead-letter volume	Kafka dead-letter topic
Anomaly trends	Persisted detection results
Host timeline	Persisted event and feature records
Ledger integrity	Ledger verification results and sealing metadata
Component health	Actual health checks against relevant services

The dashboard should distinguish zero values from unavailable measurements. A failed metric query must not be represented as evidence that the system is healthy.

⸻

AI-Powered Incident Investigation

Status: Planned

SignalOps will include an LLM-powered investigation agent that helps engineers interpret operational signals and investigate incidents.

The agent will retrieve evidence through controlled application tools rather than directly accessing unrestricted databases or executing arbitrary commands.

Investigation Workflow

Incident or Engineer Request
             |
             v
    Investigation Agent
             |
             v
    Structured Tool Calls
             |
      +------+-------+
      |              |
      v              v
Operational Data   Runbook Retrieval
      |              |
      +------+-------+
             |
             v
   Evidence Correlation
             |
             v
    Incident Summary

Proposed Tools

The agent may use a controlled set of application-level tools:

* get_pipeline_health
* get_pipeline_metrics
* get_recent_failures
* get_dlq_summary
* get_detection_details
* get_host_timeline
* get_ledger_status
* search_runbooks

Each tool should return structured data with clear error states and timestamps where available.

The agent should not invent unavailable metrics or treat a failed tool call as proof that no issue exists.

Runbook Retrieval

Runbooks will provide troubleshooting procedures for known operational situations.

Example topics include:

* Malformed or rejected records.
* Increased dead-letter volume.
* Unexpected processing delays.
* Anomaly bursts.
* Missing or inconsistent persisted records.
* Evidence-ledger verification failures.

The retrieval mechanism should return the relevant document sections and their source identifiers so the agent can distinguish documented procedures from its own interpretation.

Investigation Output

The agent should return a consistent structure:

1. Summary: A concise description of the reported issue.
2. Observed evidence: Metrics, events, errors, and timestamps actually retrieved.
3. Potential explanation: Plausible causes supported by the available evidence.
4. Relevant runbooks: Matching documentation and troubleshooting steps.
5. Recommended next steps: Safe, actionable checks.
6. Uncertainty: Missing evidence, failed queries, and alternative explanations.

The agent should explicitly label hypotheses and avoid presenting correlation as confirmed causation.

Failure Isolation

The investigation agent is an optional operational layer.

If the LLM provider is unavailable, the core ingestion, stream-processing, detection, and evidence-preservation workflows should continue operating. Dashboard and API functionality should remain available to the extent that their underlying dependencies are healthy.

⸻

Operational API

Status: Planned

A FastAPI service will expose a controlled interface for dashboards, the investigation agent, and Slack commands.

Proposed Endpoints

Method	Endpoint	Purpose
GET	/api/ops/health	Report operational health checks
GET	/api/ops/metrics	Return available pipeline metrics
GET	/api/ops/incidents	Retrieve recent incidents or investigation candidates
GET	/api/ops/dlq/summary	Summarize dead-letter activity
GET	/api/ops/detections	Retrieve anomaly detection results
GET	/api/ops/hosts/{host_id}/timeline	Retrieve a host’s available event timeline
GET	/api/ops/ledger/status	Report ledger integrity and sealing status
POST	/api/ops/investigate	Request an incident investigation

These routes are a proposed interface, not a claim that the endpoints already exist.

API Design Principles

* Use typed request and response models.
* Validate identifiers, query parameters, and request bodies.
* Apply sensible limits to time ranges and result sizes.
* Return explicit errors when data sources are unavailable.
* Keep operational endpoints read-only by default.
* Apply authentication and authorization appropriate to the deployment.
* Avoid returning secrets or unnecessary sensitive log content.
* Add request timeouts and structured logging.
* Keep LLM calls outside latency-sensitive health and metrics requests.

The investigation endpoint should accept a bounded incident context and return either a structured result or a job identifier for longer-running investigations.

⸻

Slack-Based Self-Service

Status: Planned

Slack integration will provide an engineering-facing interface to the same operational API and investigation service used by the dashboard.

The purpose is to reduce repetitive support requests and make operational information accessible without requiring engineers to manually query multiple systems.

Proposed Commands

Command	Purpose
/ops health	Retrieve current operational health information
/ops incidents	List recent incidents or investigation candidates
/ops investigate <incident_id>	Request an evidence-grounded investigation
/ops runbook <query>	Search troubleshooting documentation

Example Workflow

An engineer notices a spike in pipeline failures and requests an investigation.

SignalOps retrieves the relevant operational metrics, recent failure details, and matching runbook sections. The investigation agent then returns a concise summary that distinguishes observed evidence from possible causes.

The engineer can use the findings to decide which diagnostic or remediation steps to perform.

Integration Requirements

* Validate Slack request signatures.
* Keep bot tokens and signing secrets in environment variables or a secret manager.
* Acknowledge Slack requests quickly.
* Run longer investigations asynchronously.
* Handle duplicate requests and retries safely.
* Limit which users or channels can invoke sensitive operations.
* Avoid exposing credentials, sensitive payloads, or unrestricted log contents.
* Do not perform destructive remediation automatically.

The Slack integration should call the shared operational API rather than implementing separate business logic.

⸻

Reliability and Security

SignalOps is designed with a separation between data processing, detection, and optional investigation services.

Reliability

* Kafka decouples producers from downstream consumers.
* Spark Structured Streaming handles continuous processing.
* Invalid records can be routed to a dead-letter topic.
* PostgreSQL provides persistent structured storage.
* The evidence ledger enables integrity verification for sealed records.
* Automated tests validate critical processing and integrity behavior.
* Optional LLM services should not be required for core ingestion.

Security Considerations

* Keep credentials outside source control.
* Validate incoming event schemas.
* Apply access controls to operational APIs.
* Verify Slack request signatures before processing commands.
* Limit the agent to explicitly defined tools.
* Avoid unrestricted SQL execution and arbitrary shell access from the agent.
* Treat log content and retrieved documents as untrusted input.
* Separate observations from hypotheses in generated summaries.
* Preserve evidence integrity during investigation.

Known Reliability Gaps

The existing implementation documentation identifies areas requiring further work, including automated replay of spooled records, the unsealed ledger window, and validation of scale-out behavior.

These should remain visible limitations until addressed and verified.

⸻

Testing and Validation

The existing project documentation reports approximately 270 automated tests across the core pipeline, model, Spark, and database components. The exact total should be confirmed against the current repository because the existing documentation contains inconsistent counts.

Existing Test Areas

Area	Validation Focus
Core Pipeline	Parsing, normalization, validation, and processing behavior
Anomaly Model	Model behavior and evaluation logic
Spark	Streaming transformations and feature extraction
PostgreSQL	Persistence and relational data behavior
Evidence Ledger	Hash verification, block integrity, and inclusion proofs
Containerized Stack	End-to-end component integration

Planned Operational Tests

The observability and investigation layers should add tests covering:

* Correct aggregation of pipeline metrics.
* Missing and stale metric data.
* API validation and error handling.
* DLQ summaries and incident retrieval.
* Runbook search relevance and source attribution.
* Structured agent tool calls.
* Unsupported claims and missing evidence in investigation summaries.
* LLM provider timeouts and service unavailability.
* Slack signature validation and request retries.
* Ledger status reporting.
* End-to-end investigation of controlled pipeline failures.

The test suite should include failure scenarios rather than validating only successful requests.

Reproducibility

The project uses Docker Compose to run the local infrastructure and automated tests to validate individual components.

Performance and model metrics should always be reported with their evaluation setup and limitations, particularly because the current detection data is synthetic.

⸻

Getting Started

The existing streaming pipeline can be run independently of the planned operational layer.

Prerequisites

* Docker
* Docker Compose
* Git

Python 3.12 is used by the project for local development and testing.

1. Clone the Repository

git clone https://github.com/Dishan-D/Cyber-Forensics-Log-Anomaly-Pipeline-.git
cd Cyber-Forensics-Log-Anomaly-Pipeline-

2. Review the Configuration

Inspect the repository’s environment and Docker Compose configuration before starting the stack.

Configure any required environment variables using the project’s documented examples. Do not commit credentials or secret values.

3. Start the Infrastructure

docker compose up -d --build

This command assumes the repository’s Compose configuration defines the required services and build targets.

4. Check Service Status

docker compose ps

Review the service logs if a component fails to start:

docker compose logs --tail=100

5. Run the Tests

If the development environment and test dependencies are installed:

pytest

Use the repository’s current test configuration and documentation for any required integration-test setup.

6. Shut Down

docker compose down

If you need to remove persisted local volumes, review the Compose configuration first. Removing volumes may delete local development data.

Note: The commands above describe the documented Docker Compose workflow. Verify exact service names, configuration variables, and optional setup steps against the current repository before relying on them.

⸻

Configuration

Configuration should be supplied through environment variables or an appropriate local environment file excluded from version control.

Potential settings for the completed operational layer include:

Variable	Purpose
DATABASE_URL	PostgreSQL connection configuration
KAFKA_BOOTSTRAP_SERVERS	Kafka broker addresses
LLM_API_KEY	Credentials for the configured LLM provider
LLM_MODEL	Configured model identifier
SLACK_BOT_TOKEN	Slack bot credentials
SLACK_SIGNING_SECRET	Slack request signature validation
RUNBOOK_DIRECTORY	Location of runbook documents

These names are suggested configuration conventions for the operational layer. They should be documented as supported settings only after the corresponding implementation uses them.

Never commit populated secrets, API keys, bot tokens, or database passwords.

⸻

Roadmap

Phase 1 — Streaming Foundation

* Synthetic telemetry generation.
* Kafka-based ingestion.
* Spark Structured Streaming transformations.
* Dead-letter routing.
* PostgreSQL evidence persistence.
* Transformer-based anomaly detection.
* Tamper-evident evidence ledger.
* Automated tests for the core components.

Phase 2 — Operational Observability

* Define a consistent operational metrics model.
* Build FastAPI health and metrics endpoints.
* Expose detections, DLQ summaries, and ledger status.
* Build Streamlit and Plotly dashboards.
* Add controlled failure scenarios and metric-validation tests.

Phase 3 — AI-Assisted Investigation

* Define typed investigation tools.
* Implement runbook retrieval with source attribution.
* Add structured LLM tool calling.
* Generate evidence-grounded incident summaries.
* Distinguish observations, hypotheses, and recommendations.
* Test missing evidence, timeouts, and LLM unavailability.

Phase 4 — Engineering Self-Service

* Implement Slack request verification.
* Add operational slash commands.
* Connect Slack to the shared investigation service.
* Support asynchronous investigations.
* Add authorization, retry handling, and integration tests.

Phase 5 — Further Improvements

* Add automated replay and recovery for eligible failed records.
* Validate behavior under larger workloads and distributed failures.
* Improve model evaluation on additional datasets.
* Explore MCP-based tool interoperability if it provides a clear benefit.
* Add deployment and performance benchmarks.

⸻

Limitations

SignalOps is a development and research project, not a production-ready security monitoring service.

Current limitations include:

* Synthetic telemetry does not capture the full complexity of real enterprise environments.
* Reported model metrics are specific to the documented evaluation setup.
* Anomaly scores require contextual interpretation and do not establish malicious intent by themselves.
* Records may remain unsealed until the next ledger-sealing operation.
* Automated dead-letter replay is not yet implemented.
* Distributed scale-out and production failure scenarios require further validation.
* The operational dashboard, API, AI investigation agent, runbook retrieval, and Slack integration are planned until implemented and tested.
* LLM-generated explanations must remain grounded in retrieved evidence and should not be treated as authoritative without verification.

⸻

Project Goals

SignalOps explores the intersection of data engineering, distributed stream processing, observability, anomaly detection, and AI-assisted operations.

The project aims to demonstrate how a streaming data platform can evolve beyond processing events into helping engineers understand system behavior, identify operational issues, retrieve relevant troubleshooting knowledge, and investigate incidents more efficiently.

By combining Kafka, Spark Structured Streaming, PostgreSQL, machine learning, and a planned operational intelligence layer, SignalOps provides a foundation for building more transparent and supportable data infrastructure.

⸻

Repository: Cyber-Forensics-Log-Anomaly-Pipeline
