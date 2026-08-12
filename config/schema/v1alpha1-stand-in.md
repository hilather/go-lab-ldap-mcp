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
