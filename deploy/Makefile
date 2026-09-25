# Convenience targets for the containerised lab.
#
# The lab is defined by deploy/lab.yaml. `lab-render` turns that into
# deploy/.env and deploy/runtime/, which is what the containers actually read.
#
#   make lab-bootstrap     bare host -> working, verified lab (safe to re-run)
#   make lab-render        regenerate deploy/.env and deploy/runtime
#   make lab-up            render, then start the containers
#   make lab-down          stop the containers
#   make lab-reset         stop and drop the data volumes
#   make lab-ps            show container status
#   make lab-logs          follow container logs
#   make lab-verify        assert the running stack works
#   make lab-test          run every test layer the environment supports
#   make lab-ui            serve the configuration console
#
# `make lab-test` is the entry point for "is this environment good?": it runs the
# conformance tests, then the container, IMS, S2b and SWu integration layers,
# skipping (not failing) the ones whose components are not built.
LABCtl      ?= go run ./cmd/labctl
LAB         ?= deploy/lab.yaml
DEPLOY      ?= deploy
COMPOSE     ?= docker compose --project-directory $(DEPLOY)
UI_LISTEN   ?= 127.0.0.1:8088
PYHSS_VENV  ?= /tmp/pyhss-venv
PYHSS_PYTHON ?= $(PYHSS_VENV)/bin/python

.PHONY: build labctl lab-bootstrap lab-render lab-ui lab-up lab-down lab-reset \
        lab-ps lab-logs lab-shell lab-verify lab-test test fmt vet clean

build: labctl

labctl:
	go build -o bin/labctl ./cmd/labctl

# lab-bootstrap is the one command to run on a fresh or reset machine. It is
# idempotent: re-running it only does the work that is still missing.
lab-bootstrap:
	PYHSS_VENV=$(PYHSS_VENV) bash $(DEPLOY)/scripts/bootstrap.sh all

# render is the step that makes a lab.yaml change real for the containers.
lab-render:
	$(LABCtl) render -lab $(LAB) -deploy $(DEPLOY)

lab-ui:
	$(LABCtl) serve -lab $(LAB) -deploy $(DEPLOY) -listen $(UI_LISTEN)

# up renders first so the containers always start from the current definition.
lab-up: lab-render
	$(COMPOSE) up -d --build --remove-orphans

lab-down:
	$(COMPOSE) down

# down -v also drops the data volumes; needed when credentials change, because
# MariaDB only runs its init scripts on a fresh data directory.
lab-reset:
	$(COMPOSE) down -v --remove-orphans

lab-ps:
	$(COMPOSE) ps

lab-logs:
	$(COMPOSE) logs -f --tail=100

# lab-shell opens a shell in a container: make lab-shell SERVICE=pcscf
lab-shell:
	$(COMPOSE) exec $(SERVICE) bash

lab-verify:
	PYHSS_PYTHON=$(PYHSS_PYTHON) bash $(DEPLOY)/scripts/verify.sh

# lab-test runs every layer; pass levels to narrow it, e.g.
#   make lab-test LEVELS="unit container"
LEVELS ?=
lab-test:
	PYHSS_VENV=$(PYHSS_VENV) bash $(DEPLOY)/scripts/test-all.sh $(LEVELS)

test:
	go test ./...

fmt:
	gofmt -l -w ./cmd ./internal

vet:
	go vet ./...

clean: lab-reset
	rm -rf bin
