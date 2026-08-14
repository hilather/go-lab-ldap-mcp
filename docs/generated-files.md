# Generated files

This document is the source-versus-generated policy for LabLDAP.

## Current (T-060+)

| Path | Role |
| --- | --- |
| [`api/openapi.yaml`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/openapi.yaml) | **Source.** Author and review this file. |
| [`api/oapi-codegen.yaml`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/oapi-codegen.yaml) | **Source.** oapi-codegen configuration. |
| [`api/generated/types.gen.go`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/generated/types.gen.go) | **Generated.** Go models. Never hand-edit. |
| [`api/generated/typescript/schema.d.ts`](https://github.com/hilather/go-lab-ldap-mcp/blob/main/api/generated/typescript/schema.d.ts) | **Generated.** TypeScript types. Never hand-edit. |

Regenerate with `make generate`. Fail CI on drift with `make generate-drift`.

A later frontend OpenAPI client (T-095) consumes the generated TypeScript types. Do not duplicate those types by hand.

## OD-009 verification

```text
Decision ID: OD-009
Pinned component/version/digest: github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0; openapi-typescript@7.13.0
Environment tested: host Go 1.26.5 / toolchain go1.26.5, Node 22.14.0, pnpm 10.14.0
Commands or tests: make generate; make generate-drift; go test ./api ./internal/api ./internal/auth ./cmd/labldap
Observed behavior: oapi-codegen v2.8.0 emits deterministic Go models from OpenAPI 3.0.3. openapi-typescript 7.13.0 emits TypeScript types. OpenAPI 3.1 was not selected because request validation and examples are expressed as the documented 3.0.3 subset.
Security implications: examples contain only lab placeholders, not fixture or production secrets. Generated code is models only (no third-party HTTP router).
Result: accepted default
Related tasks: T-060, T-061
```

## Rules

1. Update generated files only through committed generation commands, never by hand.
2. Do not commit a generated-file change without the corresponding source change.
3. If generation would rewrite a file you edited by hand, revert the hand edit and change the source instead.
