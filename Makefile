GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build test race vet lint tidy gosec vulncheck sbom migrate-up migrate-down docker compose-up compose-down

all: build

build:
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/api ./cmd/api
	$(GO) build -ldflags "$(LDFLAGS)" -o bin/worker ./cmd/worker

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

gosec:
	gosec ./...

vulncheck:
	govulncheck ./...

sbom:
	syft dir:. -o cyclonedx-json=sbom.cdx.json

migrate-up:
	sql-migrate up -config=migrations/dbconfig.yml -env=development

migrate-down:
	sql-migrate down -config=migrations/dbconfig.yml -env=development

docker:
	docker build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t octo-meeting-service:$(VERSION) .

compose-up:
	docker compose up --build

compose-down:
	docker compose down -v
