# Rollback notes

This service is delivered as immutable container images with externally managed
schema migrations. Rollback has two independent axes: the running image and the
database schema. Treat them separately.

## 1. Application rollback (fast, safe)

The deployment uses a `RollingUpdate` strategy with `maxUnavailable: 0`. To roll
back to the previously known-good image tag:

```
kubectl set image deployment/octo-meeting-service api=REGISTRY/octo-meeting-service:<previous-tag>
kubectl rollout undo deployment/octo-meeting-service   # or roll back to a specific revision
kubectl rollout status deployment/octo-meeting-service
```

Repeat for `octo-meeting-worker`. Because images are immutable and build/commit
metadata is embedded (`build_info` metric, `-X main.version/commit`), the exact
running artifact is always identifiable.

## 2. Database rollback (deliberate)

Migrations are managed by `sql-migrate` and are **forward-only in production by
default**. Every migration ships with a `-- +migrate Down` section for local and
staging use, but a production down-migration must be a conscious decision:

```
sql-migrate down -config=migrations/dbconfig.yml -env=production -limit=1
```

Guidelines:
- Prefer rolling the application back to a version compatible with the current
  schema over reversing a migration.
- Design migrations to be backward-compatible (expand/contract) so an app
  rollback never requires a schema rollback.
- Never point the service at a fresh/empty database as a "recovery" shortcut —
  there is no SQLite/auto-create fallback, and doing so would drop data.

## 3. Bootstrap-specific note

This bootstrap adds only a `bootstrap_marker` baseline table and no domain data.
Its down-migration drops that table and is safe to run in any environment.

## 4. Verify after rollback

- `GET /healthz` returns 200.
- `GET /readyz` returns 200 with every dependency `ok`.
- `build_info` metric reflects the expected version/commit.
