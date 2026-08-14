# Tests

- `integration/` — real 389 DS container tests (`//go:build integration`; `make test-integration`), including T-041 bootstrap-image smoke and T-042 Compose topology
- `enginesuite/` — T-043 observed/proposed inventory (does not require `docs/03`)
- `composecontract/` — T-042 Compose file contract (no Docker)
- `e2e/` — Playwright product acceptance (T-107)
- `compatibility/` — LDAP client matrix (T-115)
- `fixtures/` — configuration and golden files (M1)

Mocks must not replace the real 389 DS integration suite for engine behavior.
