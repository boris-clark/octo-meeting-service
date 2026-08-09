# Contract snapshots — `r4-go-f0f482c0`

This directory holds the **service-owned**, authoritative OpenAPI and
error-catalog snapshots for the standalone Octo Meeting service, bound to the
approved architecture set.

- Architecture SHA-256: `f0f482c0add1cfe81edb8cdab6418c63097be995037b582c339bbaeec0a8e871`
- Go runtime revision SHA-256: `28e3712d1aa6b5db166067404770f90314ffbf3c45eaffa70a17a3f7e16ed723`

## Files

- `openapi.yaml` — the full public HTTP contract: operational probes plus the
  meeting domain surface (create/schedule/edit/cancel/list/detail, admission
  evaluate → password verify → finalize, roster/controls/share/lock/end,
  invites, and the LiveKit reconciliation webhook).
- `errors.yaml` — the frozen `MEETING_*` error taxonomy (code → HTTP status,
  retryability, safe `details` keys, and a frontend `directive`), plus the
  fixed FD-27 step-1 `admission_order`.

## Purpose

The snapshot is the single, versioned, reviewable source of truth for the
service's public contract. It is committed (not generated at runtime) so contract
changes are visible in diffs and gated by review. The frontend typed-client, MSW
fixtures, and E2E reconcile against it field-for-field; the backend route
contract tests consume the same snapshot. `octo-server` / `dmworkim` do not
publish a Meeting OpenAPI.

It is published early — while domain handlers may still be stubbed — so the
frontend (deferred items depending on the member/roster/invitation shapes) is
unblocked without waiting on handler completion.

## Conventions (frozen by the approved design)

- Gateway base: `/meeting/api/v1`; canonical service paths under `/v1`.
- Wire format: `snake_case`; timestamps are UTC ISO-8601.
- Error envelope: `{ code, message, details, request_id }`. `code` is a stable
  value from `errors.yaml`; `details` carries only that code's safe keys.
- Implementations MUST NOT add, rename, or abbreviate error codes.
- Cross-Space / unauthorized access returns an indistinguishable `404`
  (`MEETING_CREDENTIAL_INVALID`) — no existence, password-state, or lifecycle
  leak (S-1). `MEETING_NOT_SAME_SPACE` is only ever returned to a caller already
  authorized to know the meeting exists.
- No secret values (passwords, link/pass tokens, LiveKit tokens, verifiers)
  ever appear in any request/response body or error `details` defined here.

The directory name stays pinned to the architecture SHA above until a new
architecture revision supersedes it.
