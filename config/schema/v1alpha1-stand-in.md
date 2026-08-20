# v1alpha1 configuration stand-in

**Status:** dated invention (2026-08-12). **Not** an accepted ADR. **Not** recovered from `docs/02-configuration-and-domain-model.md` (that file is absent).

| Item | Value |
| --- | --- |
| `apiVersion` | `labldap.dev/v1alpha1` (proposed) |
| `kind` | `LabScenario` (proposed) |
| YAML keys | camelCase |
| JSON Schema dialect | 2020-12 (`https://json-schema.org/draft/2020-12/schema`) |
| `rawEntries` | **not present** and must not be added |
| Expected churn | If `docs/02` is recovered, diff and write a **new** ADR before renaming |

Compiler contract string (mixed into revisions in T-021): `labldap.config.v1alpha1.3`.

## Compatibility notes

- **2026-08-15 (T-123, ADR-0008 decision 7):** `spec.directory.engine` added
  (`389ds` | `native`, default `389ds`). Backward-compatible optional field:
  no `apiVersion` bump, no renames, existing scenarios compile unchanged.
  The engine value is mixed into the **directory revision hash** (a different
  engine is a different lab), so existing `389ds` scenarios see a one-time
  directory-revision change on upgrade; the control revision and the compiler
  contract string are unchanged. `native` is accepted by the schema but fails
  closed (`configuration` / `engine_not_available`) in `labldap serve` and
  `labldap-bootstrap` until milestone M9 wires it (T-146); see
  `docs/design/native-engine-parity-contract.md`.
- **2026-08-17 (v0.3.0, ADR-0008 amendment):** omitted `spec.directory.engine`
  now defaults to `native`. Stay on `apiVersion: labldap.dev/v1alpha1` (owner
  resolution: this one omitted-field reinterpretation does not take a new
  apiVersion). Compiler contract string is unchanged. Directory revision
  changes for labs that omitted the field (they are now native labs). Add
  `engine: 389ds` before upgrading if you must keep 389 DS. `labldapd`
  fails closed when `--data-dir` looks like a 389 nsslapd tree.
- **2026-08-19 (ADR-0010):** `spec.management.allowedHosts` added
  (`[]string`, default empty). Backward-compatible optional field: no
  `apiVersion` bump. Extra hosts union with `LoopbackHosts` (and, for
  loopback/bind-all listen, host-only `localhost` / `127.0.0.1` / `::1` /
  `control`). Env `LABLDAP_MANAGEMENT_ALLOWED_HOSTS` and repeatable
  `--management-allowed-host` are additional sources. `*` is rejected.
  Compiler contract string and revision hashes are unchanged.
- **2026-08-19 (ADR-0011, issue #5):** `spec.directory.additionalSuffixes`
  added (`[]string`, default empty). Backward-compatible optional field:
  no `apiVersion` bump, no `CompilerContract` bump. Omitted or empty
  keeps today's single-suffix directory revision. Non-empty lists mix
  into the directory revision. Values must be sibling naming contexts
  (not equal to the primary, not nested). Multi-domain here means
  multiple configured suffixes in one lab, not AD forests or trusts.
