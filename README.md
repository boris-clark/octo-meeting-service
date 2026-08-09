# octo-meeting-service

Standalone backend service for Octo online meetings.

> **Status: bootstrap.** This repository currently contains only the service
> skeleton, tooling, and operational scaffolding. No meeting domain or product
> logic is implemented yet. See issue #1 for the bootstrap scope.

## Runtime

Frozen Go stack (approved runtime revision `v0.1.2`, SHA-256
`28e3712d1aa6b5db166067404770f90314ffbf3c45eaffa70a17a3f7e16ed723`; derived from
architecture SHA-256
`f0f482c0add1cfe81edb8cdab6418c63097be995037b582c339bbaeec0a8e871`):

| Concern        | Choice                                        |
| -------------- | --------------------------------------------- |
| Language       | Go 1.25.x                                      |
| HTTP           | Gin                                            |
| Config         | Viper + env (`OCTO_MEETING_*`), validated boot |
| Datastore      | MySQL (`go-sql-driver/mysql`) + `sql-migrate`  |
| Cache/leases   | Redis (`go-redis/v9`)                          |
| Logging        | zap, structured, with redaction baseline       |
| Metrics        | Prometheus (`/metrics`)                        |
| Health         | `/healthz` (liveness), `/readyz` (readiness)   |

## Layout

```
cmd/api            HTTP entrypoint (health, readiness, metrics, empty /v1 group)
cmd/worker         background worker entrypoint (bounded, graceful shutdown)
internal/config    configuration schema + startup validation
internal/httpserver Gin engine, middleware, graceful HTTP servers
internal/health    liveness/readiness registry
internal/observability logging, redaction, Prometheus metrics
internal/storage   MySQL + Redis wiring and readiness checkers
internal/seams     auth/Space/notification/LiveKit interfaces (no live calls yet)
internal/worker    worker lifecycle
migrations         sql-migrate migrations (MySQL only)
contracts/snapshots/r4-go-f0f482c0  service-owned OpenAPI + error catalog
deploy             deployment template + rollback notes
```

## Local development

```
cp .env.example .env         # adjust as needed; never commit .env
docker compose up --build    # mysql + redis + api + worker
```

Then:

```
curl -s localhost:8080/healthz
curl -s localhost:8080/readyz
curl -s localhost:9090/metrics | head
```

## Build & test

```
make build      # compile api + worker
make test       # unit tests
make race       # tests with the race detector
make vet lint   # static analysis
make vulncheck gosec   # security gates
```

## Configuration

All configuration is environment-driven with the `OCTO_MEETING_` prefix; nested
keys use `__`. See `.env.example` for the full schema. MySQL and Redis are
**required** — the service fails to start without them and has no embedded/SQLite
fallback.

## Security invariants (honored by the skeleton)

- Identity is resolved only from an authenticated principal (Auth seam); the
  service never trusts client-supplied `x-user-id` / `x-org-id`.
- Realtime paths are authenticated; no unauthenticated WebSocket.
- No secret values (meeting passwords, link/pass tokens, LiveKit tokens) are
  ever logged or returned; the logging redaction baseline enforces this.
- Gateway base path `/meeting/api/v1`; canonical service paths under `/v1`;
  `snake_case` wire contract.
