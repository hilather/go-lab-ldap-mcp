# Generated files

This document is the source-versus-generated policy for LabLDAP.

## M0 (current)

Nothing in this repository is generated.

- `make generate` is a no-op (OpenAPI and clients land in T-060).
- `make generate-drift` runs `tools/gencheck`, which checks toolchain pins and the committed frontend lockfile. It does not rewrite sources.
- `api/generated/` exists only as a reserved directory (`.gitkeep`). Do not add hand-written code there.

Hand-written sources include Go under `cmd/` and `internal/`, `frontend/` placeholder scripts, `Makefile`, configuration examples, and design documents.

## After OpenAPI exists (T-060+)

| Path | Role |
| --- | --- |
| `api/openapi.yaml` | **Source.** Author and review this file (lands in T-060). |
| [`api/generated/`](https://github.com/hilather/go-lab-ldap-mcp/tree/main/api/generated) | **Generated.** Go types and related artifacts. Never hand-edit. |

Regenerate with `make generate`. Fail CI on drift with `make generate-drift`.

A later frontend OpenAPI client (T-095) is also generated. Do not duplicate those types by hand.

## Rules

1. Update generated files only through committed generation commands, never by hand.
2. Do not commit a generated-file change without the corresponding source change.
3. If generation would rewrite a file you edited by hand, revert the hand edit and change the source instead.
