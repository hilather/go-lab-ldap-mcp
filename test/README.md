# Tests

- `integration/` — real 389 DS container tests (T-025+)
- `e2e/` — Playwright product acceptance (T-107)
- `compatibility/` — LDAP client matrix (T-115)
- `fixtures/` — configuration and golden files (M1)

Mocks must not replace the real 389 DS integration suite for engine behavior.
