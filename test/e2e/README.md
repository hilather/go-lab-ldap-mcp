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

Tokens and bind passwords are not committed. Playwright records `fill()`
values and JSON bodies in `trace.zip`. That zip is rewritten in global
teardown: text members have fixture/`LABLDAP_E2E_*` secrets replaced with
`[redacted]`. Page snapshots and screenshots inside the trace are disabled
so password fields are not stored as pixels. Standalone failure PNGs that
still contain a secret as UTF-8 bytes are replaced with a 1x1 placeholder.

`clearPasswordFields` in `afterEach` is not the redaction path (Playwright
attaches traces after hooks). Do not attach `test-results/` from a run
that failed before teardown finished.
