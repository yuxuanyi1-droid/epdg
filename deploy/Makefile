# Convenience targets for the containerised lab.
#
#   make lab-render        regenerate deploy/.env and deploy/runtime from lab.yaml
#   make lab-ui            serve the configuration UI on 127.0.0.1:8088
#   make lab-up            render, then start the containers
#   make lab-down          stop the containers
#   make lab-ps            show the container status
#   make lab-logs          follow the container logs
#   make test              run the Go unit tests
LABCtl      ?= go run ./cmd/labctl
LAB         ?= deploy/lab.yaml
DEPLOY      ?= deploy
COMPOSE     ?= docker compose --project-directory $(DEPLOY)
UI_LISTEN   ?= 127.0.0.1:8088

.PHONY: build labctl lab-render lab-ui lab-up lab-down lab-ps lab-logs lab-shell lab-verify test fmt vet clean

build: labctl

labctl:
	go build -o bin/labctl ./cmd/labctl

# render is the step that makes a lab.yaml change real for the containers.
lab-render:
	$(LABCtl) render -lab $(LAB) -deploy $(DEPLOY)

lab-ui:
	$(LABCtl) serve -lab $(LAB) -deploy $(DEPLOY) -listen $(UI_LISTEN)

# up renders first so the containers always start from the current definition.
lab-up: lab-render
	$(COMPOSE) up -d --build

lab-down:
	$(COMPOSE) down

lab-ps:
	$(COMPOSE) ps

lab-logs:
	$(COMPOSE) logs -f --tail=100

# lab-shell opens a shell in a container: make lab-shell SERVICE=pcscf
lab-shell:
	$(COMPOSE) exec $(SERVICE) bash

# lab-verify checks that the containers came up and that the signalling paths
# work. It needs the stack to be running.
lab-verify:
	bash deploy/scripts/verify.sh

test:
	go test ./...

fmt:
	gofmt -l -w ./cmd ./internal

vet:
	go vet ./...

clean:
	rm -rf bin
	$(COMPOSE) down -v --remove-orphans
