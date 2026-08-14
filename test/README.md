# Tests

- `integration/` — real 389 DS container tests (`//go:build integration`; `make test-integration`), including bootstrap-image smoke, Compose topology, and T-113 TLS helper LDAPS/StartTLS
- `enginesuite/` — T-043 observed/proposed inventory (does not require `docs/03`)
- `composecontract/` — T-110/T-111 Compose file contract (no Docker)
- `imagecontract/` — T-108 / T-109 Dockerfile pin and hardening contract (no Docker)
- `e2e/` — Playwright product acceptance (T-107). `make test-e2e` runs against a contract mock unless `LABLDAP_E2E_BASE_URL` is set.
- `compatibility/` — LDAP client matrix (T-115)
- `fixtures/` — configuration and golden files (M1)

Mocks must not replace the real 389 DS integration suite for engine behavior.
