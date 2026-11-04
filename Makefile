# NETY — every target runs inside Docker: nothing is installed on the host.
#
#   make build     build the static linux binaries into ./dist
#   make test      run the Go test suite
#   make vet       go vet + gofmt check
#   make web       build the SPA only
#   make shell     interactive shell in the toolchain image
#   make image     build the runtime container image (ghcr style)
#   make lab-up    start the multi-VLAN integration lab
#   make lab-down  tear the lab down
#   make clean     remove build output

SHELL      := /bin/bash
PROJECT    := nety
TOOL_IMAGE := nety-toolchain:latest
RUN_IMAGE  := nety:latest
# Architecture of the lab containers, which follow the host.
HOST_ARCH  := $(shell uname -m)
ifeq ($(filter arm64 aarch64,$(HOST_ARCH)),)
LAB_ARCH   := amd64
else
LAB_ARCH   := arm64
endif
UID        := $(shell id -u)
GID        := $(shell id -g)
PWD        := $(shell pwd)
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE       := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS    := -s -w \
	-X github.com/vaadata/nety/internal/config.Version=$(VERSION) \
	-X github.com/vaadata/nety/internal/config.Commit=$(COMMIT) \
	-X github.com/vaadata/nety/internal/config.BuildDate=$(DATE)

# Docker invocation used for every toolchain command. Caches live in .cache/
# so repeated builds are fast and nothing lands outside the project.
DOCKER_RUN = docker run --rm -t \
	-u $(UID):$(GID) \
	-v $(PWD):/src -w /src \
	-v $(PWD)/.cache/go-build:/.cache/go-build \
	-v $(PWD)/.cache/go-mod:/go/pkg/mod \
	-v $(PWD)/.cache/npm:/.npm \
	-e GOCACHE=/.cache/go-build \
	-e GOMODCACHE=/go/pkg/mod \
	-e GOFLAGS=-buildvcs=false \
	-e CGO_ENABLED=0 \
	-e HOME=/tmp \
	$(TOOL_IMAGE)

.PHONY: all build test vet fmt web shell image lab-up lab-down clean toolchain

all: build

## Build the toolchain image (Go + Node) once; cached afterwards.
toolchain:
	@mkdir -p .cache/go-build .cache/go-mod .cache/npm
	@docker image inspect $(TOOL_IMAGE) >/dev/null 2>&1 || \
		docker build -f build/Dockerfile.toolchain -t $(TOOL_IMAGE) build

## Force a rebuild of the toolchain image.
toolchain-rebuild:
	docker build --no-cache -f build/Dockerfile.toolchain -t $(TOOL_IMAGE) build

web: toolchain
	$(DOCKER_RUN) bash -c 'cd web && npm ci --no-audit --no-fund && npm run build'

build: toolchain web
	$(DOCKER_RUN) bash -c '\
		mkdir -p dist && \
		GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/nety-linux-amd64 ./cmd/nety && \
		GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/nety-linux-arm64 ./cmd/nety && \
		ls -lh dist/'

## Build without rebuilding the SPA (fast iteration on Go code).
build-go: toolchain
	$(DOCKER_RUN) bash -c '\
		mkdir -p dist && \
		GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/nety-linux-amd64 ./cmd/nety'

test: toolchain
	$(DOCKER_RUN) go test ./... $(TESTFLAGS)

test-race: toolchain
	$(DOCKER_RUN) bash -c 'CGO_ENABLED=1 go test -race ./...'

vet: toolchain
	$(DOCKER_RUN) bash -c 'go vet ./... && test -z "$$(gofmt -l $$(find . -name "*.go" -not -path "./.cache/*"))"'

fmt: toolchain
	$(DOCKER_RUN) bash -c 'gofmt -w $$(find . -name "*.go" -not -path "./.cache/*")'

tidy: toolchain
	$(DOCKER_RUN) go mod tidy

shell: toolchain
	docker run --rm -it -u $(UID):$(GID) -v $(PWD):/src -w /src \
		-v $(PWD)/.cache/go-build:/.cache/go-build -v $(PWD)/.cache/go-mod:/go/pkg/mod \
		-e GOCACHE=/.cache/go-build -e GOMODCACHE=/go/pkg/mod -e HOME=/tmp \
		$(TOOL_IMAGE) bash

## Runtime image: the binary plus the capabilities it needs.
image:
	docker build -f build/Dockerfile -t $(RUN_IMAGE) \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) .

## Integration lab: NETY plus a set of isolated networks with real services.
## It runs the binary build/ produced, so the lab exercises what ships.
lab-up: build
	docker compose -f build/lab/docker-compose.yml up -d --build

## Exercise the raw-socket and netlink paths against a real kernel inside the
## lab. It reconfigures the lab container's interfaces, never your machine.
lab-verify: toolchain
	$(DOCKER_RUN) env GOOS=linux GOARCH=$(LAB_ARCH) go build -o dist/labcheck ./cmd/labcheck
	docker cp dist/labcheck nety-lab:/usr/local/bin/labcheck
	docker exec nety-lab labcheck

lab-down:
	docker compose -f build/lab/docker-compose.yml down -v

lab-logs:
	docker compose -f build/lab/docker-compose.yml logs -f

clean:
	rm -rf dist web/dist internal/server/dist/assets internal/server/dist/index.html
