# Developer entrypoints. `make help` lists everything.
.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE := docker compose

# psql inside the container prompts for a password without this. Read from .env
# so the targets work straight after `make up` rather than hanging on a prompt.
PGPASS := -e PGPASSWORD="$$(grep -s '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)"
PSQL   := $(COMPOSE) exec -T $(PGPASS) postgres psql -U $${POSTGRES_USER:-forensics} -d $${POSTGRES_DB:-forensics}
PYTHON  := python3
VENV    := .venv

# Spark needs its own environment: driver and workers must share a Python minor
# version, and Spark 4.0 runs on Java 17/21 (Java 24+ removed the Security
# Manager APIs Hadoop still calls).
PYTHON_SPARK     := python3.11
VENV_SPARK       := .venv-spark
# Resolved by a script that verifies the version it is handed: on this machine
# `/usr/libexec/java_home -v 21` returns JDK 25, which Spark cannot use.
JAVA_HOME_SPARK  ?= $(shell ./scripts/find-java.sh)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# --------------------------------------------------------------------------- #
# Local development                                                            #
# --------------------------------------------------------------------------- #

.PHONY: venv
venv: ## Create the local virtualenv and install dev dependencies
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements-dev.txt

.PHONY: venv-spark
venv-spark: ## Create the Spark test venv (needs Python 3.11/3.12 + JDK 17 or 21)
	$(PYTHON_SPARK) -m venv $(VENV_SPARK)
	$(VENV_SPARK)/bin/pip install --upgrade pip
	$(VENV_SPARK)/bin/pip install pyspark==4.0.0 pytest torch
	$(VENV_SPARK)/bin/pip install -e . --no-deps

.PHONY: test
test: ## Run the core suite (no Kafka, Spark or Postgres needed)
	$(VENV)/bin/pytest tests --ignore=tests/spark --ignore=tests/db

.PHONY: test-spark
test-spark: ## Run the Spark suite (needs venv-spark and JAVA_HOME on JDK 17/21)
	JAVA_HOME=$(JAVA_HOME_SPARK) PYTHONPATH=src:. \
		$(VENV_SPARK)/bin/pytest tests/spark

.PHONY: test-db
test-db: ## Run the database suite (DESTRUCTIVE — truncates evidence + ledger)
	@echo "WARNING: this TRUNCATEs evidence.*, analytics.* and ledger.* in"
	@echo "         $${POSTGRES_DB:-forensics} on $${POSTGRES_HOST:-localhost}:$${POSTGRES_PORT:-5432}."
	@echo "         Point POSTGRES_DB at a throwaway database, not the running stack."
	@printf "         continue? [y/N] " && read ans && [ "$$ans" = "y" ]
	$(VENV)/bin/pytest tests/db

.PHONY: test-db-force
test-db-force: ## Same, without the confirmation prompt (for CI)
	$(VENV)/bin/pytest tests/db

.PHONY: test-model
test-model: ## Run the detector suite (needs torch; installed in venv-spark)
	PYTHONPATH=src:. $(VENV_SPARK)/bin/pytest tests/model -p no:warnings

.PHONY: test-all
test-all: test test-spark test-model test-db ## Run every suite

.PHONY: cov
cov: ## Run tests with a coverage report
	$(VENV)/bin/pytest --cov=forensics --cov-report=term-missing

.PHONY: lint
lint: ## Lint with ruff
	$(VENV)/bin/ruff check .

.PHONY: fmt
fmt: ## Auto-fix lint findings
	$(VENV)/bin/ruff check . --fix

.PHONY: typecheck
typecheck: ## Static type check with mypy
	$(VENV)/bin/mypy

.PHONY: check
check: lint typecheck test ## Lint, typecheck and run the core suite

.PHONY: demo
demo: ## Print 20 sample events to stdout (no broker required, pipeable to jq)
	@PYTHONPATH=src PRODUCER_DRY_RUN=true PRODUCER_MAX_EVENTS=20 \
	PRODUCER_EVENTS_PER_SECOND=50 PRODUCER_ANOMALY_RATE=0.2 \
	$(VENV)/bin/python -m forensics.ingestion.log_producer

# --------------------------------------------------------------------------- #
# Stack                                                                        #
# --------------------------------------------------------------------------- #

.env: ## Create .env from the template if missing
	@test -f .env || (cp .env.example .env && echo "created .env from .env.example")

.PHONY: up
up: .env ## Build and start the full stack
	$(COMPOSE) up -d --build

.PHONY: down
down: ## Stop the stack (volumes preserved)
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and DELETE all data volumes
	$(COMPOSE) down -v --remove-orphans

.PHONY: logs
logs: ## Tail logs from every service
	$(COMPOSE) logs -f

.PHONY: producer-logs
producer-logs: ## Tail the producer's structured logs
	$(COMPOSE) logs -f producer

.PHONY: ps
ps: ## Show service status
	$(COMPOSE) ps

.PHONY: tools
tools: ## Start optional tooling (Kafka UI on :8080)
	$(COMPOSE) --profile tools up -d kafka-ui

# --------------------------------------------------------------------------- #
# Inspection                                                                   #
# --------------------------------------------------------------------------- #

.PHONY: topics
topics: ## List Kafka topics
	$(COMPOSE) exec kafka /opt/kafka/bin/kafka-topics.sh \
		--bootstrap-server localhost:9092 --describe

.PHONY: consume
consume: ## Tail live events from logs.raw
	$(COMPOSE) exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
		--bootstrap-server localhost:9092 \
		--topic logs.raw --from-beginning --max-messages 20 \
		--property print.key=true --property key.separator=' | '

.PHONY: lag
lag: ## Show consumer group offsets and lag
	$(COMPOSE) exec kafka /opt/kafka/bin/kafka-consumer-groups.sh \
		--bootstrap-server localhost:9092 --all-groups --describe

.PHONY: psql
psql: ## Open a psql shell on the evidence store
	$(COMPOSE) exec $(PGPASS) postgres psql -U $${POSTGRES_USER:-forensics} -d $${POSTGRES_DB:-forensics}

.PHONY: migrate
migrate: ## Apply pending database migrations
	$(COMPOSE) run --rm migrate

.PHONY: migrate-status
migrate-status: ## Show applied vs pending migrations
	$(COMPOSE) run --rm migrate python /app/scripts/migrate.py --status

.PHONY: spark-logs
spark-logs: ## Tail the Spark streaming job
	$(COMPOSE) logs -f spark

.PHONY: seed
seed: ## Load generated evidence straight into PostgreSQL (no Kafka/Spark needed)
	$(VENV)/bin/python scripts/seed_evidence.py --events $${EVENTS:-20000} --seal

.PHONY: seed-local
seed-local: ## Same, against a directly reachable PostgreSQL
	$(VENV)/bin/python scripts/seed_evidence.py --events $${EVENTS:-20000}

.PHONY: normalize
normalize: ## Drain the landing table into the 3NF evidence model
	$(PSQL) \
		-c "SELECT * FROM evidence.normalize_raw_events(20000);"

.PHONY: train
train: ## Train the LogBERT detector (writes to the model-artifacts volume)
	$(COMPOSE) --profile train run --rm trainer

.PHONY: train-local
train-local: ## Train locally with the torch venv (no Docker)
	PYTHONPATH=src $(VENV_SPARK)/bin/python scripts/train_detector.py \
		--epochs 30 --anomaly-rate 0.01 --target-fpr 0.01 \
		--out artifacts/logbert --report artifacts/report.json

.PHONY: detect
detect: ## Start the streaming scorer (requires a trained model)
	$(COMPOSE) --profile detect up -d scorer

.PHONY: scorer-logs
scorer-logs: ## Tail the scorer
	$(COMPOSE) logs -f scorer

.PHONY: alerts
alerts: ## Show the most recent flagged detections
	$(PSQL) -c "\
		SELECT host_name, window_start, round(score::numeric, 2) AS score, signals \
		FROM analytics.detections WHERE flagged \
		ORDER BY window_start DESC LIMIT 20;"

.PHONY: detection-quality
detection-quality: ## Precision/recall of stored detections against ground truth
	$(PSQL) -c "\
		SELECT count(*) FILTER (WHERE flagged AND is_anomaly) AS tp, \
		       count(*) FILTER (WHERE flagged AND NOT is_anomaly) AS fp, \
		       count(*) FILTER (WHERE NOT flagged AND is_anomaly) AS fn, \
		       round(count(*) FILTER (WHERE flagged AND is_anomaly)::numeric \
		             / NULLIF(count(*) FILTER (WHERE flagged), 0), 3) AS precision, \
		       round(count(*) FILTER (WHERE flagged AND is_anomaly)::numeric \
		             / NULLIF(count(*) FILTER (WHERE is_anomaly), 0), 3) AS recall \
		FROM analytics.detection_truth;"

.PHONY: ledger-status
ledger-status: ## Ledger head, block count and unsealed backlog
	$(PSQL) \
		-c "SELECT * FROM ledger.chain_status;"

.PHONY: ledger-seal
ledger-seal: ## Seal any pending evidence into the chain
	$(PSQL) \
		-c "SELECT * FROM ledger.seal_block(10000);"

.PHONY: ledger-verify
ledger-verify: ## Verify the chain from OUTSIDE the database (exit 1 if tampered)
	$(COMPOSE) run --rm sealer python /app/scripts/verify_ledger.py --seal

.PHONY: ledger-verify-local
ledger-verify-local: ## Verify against a directly reachable PostgreSQL
	$(VENV)/bin/python scripts/verify_ledger.py --seal

.PHONY: ledger-prove
ledger-prove: ## Inclusion proof for one event: make ledger-prove EVENT=<uuid>
	@test -n "$(EVENT)" || (echo "usage: make ledger-prove EVENT=<event-uuid>" && exit 2)
	$(COMPOSE) run --rm sealer python /app/scripts/verify_ledger.py --prove "$(EVENT)"

.PHONY: evidence
evidence: ## Row counts across the evidence model
	$(PSQL) -c "\
		SELECT 'raw_events' t, count(*) FROM evidence.raw_events \
		UNION ALL SELECT 'events', count(*) FROM evidence.events \
		UNION ALL SELECT 'hosts', count(*) FROM evidence.hosts \
		UNION ALL SELECT 'users', count(*) FROM evidence.users \
		UNION ALL SELECT 'addresses', count(*) FROM evidence.network_addresses \
		UNION ALL SELECT 'labels', count(*) FROM analytics.event_labels;"

.PHONY: dlq
dlq: ## Show the producer's dead-letter spool
	$(COMPOSE) exec producer sh -c 'cat /var/spool/forensics/dlq.jsonl 2>/dev/null || echo "spool is empty"'
