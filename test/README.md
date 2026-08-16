# Tests

- `integration/` — engine tests (`//go:build integration`). `make test-integration` is 389 DS (Docker). `make test-integration-native` is the same suite against in-process `labldapd`. Contract cases must pass on both; 389-only skips are the Delta/Excluded ledger in `dirsrv/engine.go`. Includes REST→LDAP workflow battery (`TestRESTAccountWorkflowLDAPTools`), bootstrap-image smoke, Compose topology, and T-113 TLS helper LDAPS/StartTLS.
- `enginesuite/` — T-043 observed/proposed inventory (does not require `docs/03`)
- `composecontract/` — T-110/T-111 Compose file contract (no Docker)
- `imagecontract/` — T-108 / T-109 Dockerfile pin and hardening contract (no Docker)
- `e2e/` — Playwright product acceptance (T-107). `make test-e2e` runs against a contract mock unless `LABLDAP_E2E_BASE_URL` is set.
- `compatibility/` — LDAP client matrix report + independent Go and Python clients (T-115). CI installs `ldap-utils`; missing host clients fail rather than skip.
- `parity/` — dual-engine Contract comparison (M9 / T-147). 389 DS is the oracle. Empty until T-147.
- `inspect/` — Compose/image hardening contract (T-114; live inspect is `test/integration/compose`)
- `release/` — operator package + example validation + tag-checklist contract (T-119 / T-120)
- `fixtures/` — configuration and golden files (M1)

Mocks must not replace the real 389 DS integration suite for engine behavior.
