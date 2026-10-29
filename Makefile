# Makefile — red-alert
#
#   make help        list targets
#   make doctor      report which optional analysis tools are present
#   make baseline    defensive security baseline over this repository
#   make triage FILE static triage of an artifact
#   make ledger      validate the evidence ledger
#   make test        self-tests for the tooling

SHELL := /bin/bash
REPO_ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
PYTHON ?= python3
EVIDENCE_LEDGER ?= $(REPO_ROOT)/evidence/ledger.md

.DEFAULT_GOAL := help
.PHONY: help bootstrap doctor baseline secret-scan sca triage ledger report test lint clean
.PHONY: pipeline-validate pipeline-plan pipeline-run pipeline-surface
.PHONY: webapp-validate webapp-plan webapp-collect webapp-report webapp-serve webapp-agent
.PHONY: test-targets

help: ## Show this help
	@echo "red-alert targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Usage examples:"
	@echo "  make triage /path/to/artifact"
	@echo "  make webapp-collect WEBAPP_SPEC=examples/collection-spec.example.json"
	@echo "  make webapp-serve"
	@echo "  make baseline"
	@echo "  make test"

bootstrap: ## Check prerequisites and create the working directories
	@command -v $(PYTHON) >/dev/null 2>&1 || { echo "python3 is required"; exit 1; }
	@command -v git >/dev/null 2>&1 || { echo "git is required"; exit 1; }
	@mkdir -p "$(REPO_ROOT)/evidence" "$(REPO_ROOT)/labs" "$(REPO_ROOT)/reports"
	@if [ ! -f "$(REPO_ROOT)/evidence/ledger.md" ]; then \
	  cp "$(REPO_ROOT)/templates/evidence-record.md" "$(REPO_ROOT)/evidence/ledger.md"; \
	  echo "initialised evidence/ledger.md from the template"; \
	fi
	@$(PYTHON) --version
	@echo "workspace ready: $(REPO_ROOT)"

doctor: ## Report which optional analysis tools are available
	@echo "core"
	@for tool in $(PYTHON) git file strings shasum xxd jq; do \
	  if command -v $$tool >/dev/null 2>&1; then printf "  %-10s yes\n" "$$tool"; \
	  else printf "  %-10s no\n" "$$tool"; fi; done
	@echo "optional analysis engines (missing = coverage gap, not a blocker)"
	@for tool in ghidra analyzeHeadless hopper ida64 rizin rabin2 jadx apktool adb frida mitmdump tshark capinfos binwalk unblob; do \
	  if command -v $$tool >/dev/null 2>&1; then printf "  %-14s yes\n" "$$tool"; \
	  else printf "  %-14s no\n" "$$tool"; fi; done
	@echo "optional audit tools"
	@for tool in npm pip-audit cargo govulncheck osv-scanner gitleaks semgrep shellcheck; do \
	  if command -v $$tool >/dev/null 2>&1; then printf "  %-14s yes\n" "$$tool"; \
	  else printf "  %-14s no\n" "$$tool"; fi; done

baseline: ## Run the defensive security baseline over this repository
	@scripts/sec/baseline.sh --path "$(REPO_ROOT)" --format text

secret-scan: ## Scan this repository for credential leaks
	@$(PYTHON) scripts/sec/secret_scan.py "$(REPO_ROOT)"

sca: ## Audit dependencies for the ecosystems present
	@scripts/sec/sca_audit.sh "$(REPO_ROOT)"

triage: ## Static triage of FILE (make triage FILE=/path/to/artifact)
	@if [ -z "$(FILE)" ]; then echo "usage: make triage FILE=/path/to/artifact"; exit 2; fi
	@scripts/re/triage.sh "$(FILE)"

ledger: ## Validate the evidence ledger
	@$(PYTHON) scripts/re/ledger.py "$(EVIDENCE_LEDGER)" --check

report: ## Render the report skeleton from the ledger
	@$(PYTHON) scripts/re/ledger.py "$(EVIDENCE_LEDGER)" --report --out "$(REPO_ROOT)/reports/ledger-section.md"

lint: ## Syntax-check every script
	@set -e; for script in scripts/re/*.sh scripts/sec/*.sh; do bash -n "$$script"; done
	@$(PYTHON) -m compileall -q scripts
	@$(PYTHON) -m compileall -q pipeline
	@$(PYTHON) -m compileall -q webapp
	@$(PYTHON) -m compileall -q examples
	@echo "syntax OK"

test: lint ## Run the tooling self-tests
	@$(PYTHON) scripts/re/selftest.py
	@$(PYTHON) scripts/re/selftest_webapp.py

clean: ## Remove generated working directories (keeps tracked files)
	@rm -rf "$(REPO_ROOT)/.redalert" "$(REPO_ROOT)/labs/triage-*" "$(REPO_ROOT)/reports/ledger-section.md"
	@rm -rf "$(REPO_ROOT)/.cache"
	@find "$(REPO_ROOT)" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned"

# ---------------------------------------------------------------- pipeline

PIPELINE_SPEC ?= examples/pipeline-spec.example.json
PIPELINE_CAPTURE ?= examples/capture.example.json

pipeline-validate: ## Check a pipeline specification (make pipeline-validate PIPELINE_SPEC=path)
	@$(PYTHON) -m pipeline validate "$(PIPELINE_SPEC)"

pipeline-plan: ## Show the request plan for a specification, sending nothing
	@$(PYTHON) -m pipeline plan "$(PIPELINE_SPEC)"

pipeline-run: ## Run a specification (make pipeline-run PIPELINE_SPEC=path [DRY_RUN=1])
	@if [ "$(DRY_RUN)" = "1" ]; then \
	  $(PYTHON) -m pipeline run "$(PIPELINE_SPEC)" --dry-run; \
	else \
	  $(PYTHON) -m pipeline run "$(PIPELINE_SPEC)"; \
	fi

pipeline-surface: ## Reconstruct an API surface from a capture (make pipeline-surface PIPELINE_CAPTURE=path)
	@$(PYTHON) -m pipeline surface "$(PIPELINE_CAPTURE)" --out "$(REPO_ROOT)/labs/surface-spec.json" --report

# -------------------------------------------------------------------- webapp

WEBAPP_SPEC ?= examples/collection-spec.example.json
WEBAPP_WORK ?= labs/demo/work
WEBAPP_DATASET ?= labs/demo/work/dataset.json
WEBAPP_AGENT_WORK ?= labs/demo/agent

webapp-validate: ## Check a collection specification (make webapp-validate WEBAPP_SPEC=path)
	@$(PYTHON) -m webapp validate "$(WEBAPP_SPEC)"

webapp-plan: ## Show the requests a collection would make, sending nothing
	@$(PYTHON) -m webapp plan "$(WEBAPP_SPEC)"

webapp-collect: ## Collect, extract, and report (make webapp-collect WEBAPP_SPEC=path WEBAPP_WORK=dir)
	@$(PYTHON) -m webapp collect "$(WEBAPP_SPEC)" --out "$(WEBAPP_WORK)" --report "$(WEBAPP_WORK)/report.pdf"

webapp-report: ## Render the PDF report from a dataset (make webapp-report WEBAPP_WORK=dir)
	@$(PYTHON) -m webapp report "$(WEBAPP_WORK)/dataset.json" --out "$(WEBAPP_WORK)/report.pdf"

test-targets: ## Run the recon over a matrix of public targets (make test-targets)
	@if [ "$(AUTHORIZED)" != "1" ] || [ -z "$(ONLY)" ]; then \
	  echo "usage: make test-targets AUTHORIZED=1 ONLY=target-name (permission required for every selected target)"; exit 2; fi
	@$(PYTHON) scripts/re/selftest_targets.py --authorized --only "$(ONLY)"

webapp-serve: ## Run the console (make webapp-serve WEBAPP_SPEC=path WEBAPP_WORK=dir PORT=8765)
	@$(PYTHON) -m webapp serve "$(WEBAPP_SPEC)" --work "$(WEBAPP_WORK)" --port $(or $(PORT),8765)

webapp-agent: ## Run the red-team agent over a recon dataset (make webapp-agent WEBAPP_DATASET=path)
	@$(PYTHON) -m webapp agent "$(WEBAPP_DATASET)" --out "$(WEBAPP_AGENT_WORK)" \
		--model-endpoint "$(or $(MODEL_ENDPOINT),http://127.0.0.1:11434)" \
		--model "$(or $(MODEL),llama3.1)" --authorized
