GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build test race vet lint tidy gosec vulncheck sbom migrate-up migrate-down docker compose-up compose-down integration integration-down

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

# Host-visible DSNs for the integration stack (compose maps mysql/redis to localhost).
IT_MYSQL_DSN ?= octo:octo@tcp(127.0.0.1:3306)/octo_meeting?parseTime=true&charset=utf8mb4&loc=UTC
IT_REDIS_ADDR ?= 127.0.0.1:6379

# Bring up MySQL+Redis, apply migrations, and run the tag-gated integration
# tests end-to-end (create -> resolve -> start-live, verifier, cooldown, pass token).
integration:
	docker compose up -d --wait mysql redis
	OCTO_MEETING_MYSQL__DSN="$(IT_MYSQL_DSN)" sql-migrate up -config=migrations/dbconfig.yml -env=development
	MEETING_IT_MYSQL_DSN="$(IT_MYSQL_DSN)" MEETING_IT_REDIS_ADDR="$(IT_REDIS_ADDR)" \
		$(GO) test -tags integration -count=1 -v ./test/integration/...

integration-down:
	docker compose down -v
