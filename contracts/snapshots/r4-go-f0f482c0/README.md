# Contract snapshots — `r4-go-f0f482c0`

This directory holds the **service-owned** OpenAPI and error-catalog snapshots
that are bound to the approved architecture set.

- Architecture SHA-256: `f0f482c0add1cfe81edb8cdab6418c63097be995037b582c339bbaeec0a8e871`
- Go runtime revision SHA-256: `28e3712d1aa6b5db166067404770f90314ffbf3c45eaffa70a17a3f7e16ed723`

## Purpose

The snapshot is the versioned, reviewable source of truth for the service's
public HTTP contract. It is committed to the repository (not generated at
runtime) so that contract changes are visible in diffs and gated by review.

## Scope in the bootstrap

Only the operational surface is defined here (`/healthz`, `/readyz`, `/metrics`)
plus the shared error envelope. Meeting domain paths are added under the same
directory as the domain work lands, keeping the snapshot directory name pinned
to the architecture SHA above until a new architecture revision supersedes it.

## Conventions (preserved from the approved design)

- Gateway base: `/meeting/api/v1`; canonical service paths under `/v1`.
- Wire format: `snake_case` fields.
- Cross-Space resources return an indistinguishable `404` (no existence leak).
- No secret values (passwords, link/pass tokens, LiveKit tokens) ever appear in
  request or response bodies defined here.
