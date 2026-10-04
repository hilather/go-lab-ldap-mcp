# Playwright product acceptance (T-107)

`make test-e2e` builds the frontend, starts a contract mock of the control
plane, and runs Playwright (Chromium) against the production UI.

The mock is not a 389 DS stand-in for engine behavior. Integration tests
under `test/integration` remain the engine suite.

## Live stack

The repository provides native and 389 DS Compose topologies. To use an
external stack, configure its URL and fixture credentials:

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

The default and CI browser suites run against the contract mock. This does
not establish live Compose browser acceptance or engine parity. External-URL
mode requires matching fixture data and trusted management TLS; mock-specific
assertions and outage injection (`POST /__e2e/outage`) need a corresponding
live fixture strategy. Real-engine integration and dual-engine parity remain
separate release gates. The complete acceptance/outage suite still needs a live CI fixture strategy;
the focused native Compose smoke below is automated: `make verify` runs it when
Docker is available, and CI runs it in the `e2e-live` job.

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

## Isolated live native smoke

`make test-e2e-live` builds candidate images, generates restricted temporary
credentials and TLS files, starts a unique native Compose project, and exercises
account lock/unlock, password expiry, password setting with must-change, and
structured entry create/edit/move/delete through the UI. Independent `ldapsearch`
checks prove the edited and moved entries exist in the actual directory, and that
the deleted entry is gone (exit status 32, `noSuchObject`). `make verify` runs it
when Docker is available and CI runs it in the `e2e-live` job; on failure CI
uploads the Compose service logs (set `LABLDAP_E2E_LIVE_LOG_FILE` locally for the
same). It
requires Docker, Compose 2.24.4+, host `ldapsearch`, Go, pnpm, and Playwright
Chromium (`pnpm exec playwright install chromium` from this directory).

Use `LABLDAP_E2E_LIVE_STORAGE=persistent make test-e2e-live` for named-volume mode.
The default uses ephemeral storage. Both remove only their own Compose project,
volumes, and generated credentials on completion. Default host ports are 18443
(management) and 13636 (LDAPS), configurable with `LABLDAP_E2E_LIVE_PORT` and
`LABLDAP_E2E_LIVE_LDAP_PORT`.

The harness validates the generated management certificate chain and localhost
name, then trusts only its exact public-key pin in Chromium; it never disables
all certificate checks or edits your browser trust database. LDAP checks require
the generated CA with certificate verification enabled. This focused smoke is
separate from the mock-dependent full acceptance/outage suite.
