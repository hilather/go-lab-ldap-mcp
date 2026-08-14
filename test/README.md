# Tests

- `integration/` — real 389 DS container tests (`//go:build integration`; `make test-integration`)
- `e2e/` — Playwright product acceptance (T-107). `make test-e2e` runs against a contract mock unless `LABLDAP_E2E_BASE_URL` is set. Release-like Compose + real 389 DS remains residual until T-042.
- `compatibility/` — LDAP client matrix (T-115)
- `fixtures/` — configuration and golden files (M1)

Mocks must not replace the real 389 DS integration suite for engine behavior.
