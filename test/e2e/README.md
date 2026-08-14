# Playwright product acceptance (T-107)

`make test-e2e` builds the frontend, starts a contract mock of the control
plane, and runs Playwright (Chromium) against the production UI.

The mock is not a 389 DS stand-in for engine behavior. Integration tests
under `test/integration` remain the engine suite.

## Live stack

When a release-like Compose topology exists (T-042 / T-110), point the
suite at it:

```text
export LABLDAP_E2E_BASE_URL=https://127.0.0.1:8443
export LABLDAP_E2E_ADMIN_TOKEN=...
export LABLDAP_E2E_READ_TOKEN=...
export LABLDAP_E2E_BIND_PASSWORD=...
export LABLDAP_E2E_SCENARIO_NAME=example-lab
export LABLDAP_E2E_REVISION=<compiled directory revision>
make test-e2e
```

## Residual

T-042 Compose targets are still pending on this branch, so this milestone
does **not** run against a real 389 DS Compose topology by default. The
product-acceptance and outage specs execute against the mock; outage
injection (`POST /__e2e/outage`) is mock-only.

## Secrets in artifacts

Tokens and bind passwords are not committed. Failure traces are scrubbed
by `helpers/redact.mjs` in `afterEach` and global teardown. Do not attach
unredacted `test-results/` to issues.
