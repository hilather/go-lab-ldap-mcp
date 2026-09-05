# Tag checklist (T-120)

Confirm the root `LICENSE` is MIT. Do not push images (OD-004).

1. Clean checkout of the tag candidate (`git status` empty).
2. `make verify` passes.
3. `make image` and `make image-bootstrap` report the same `version=`.
4. `make compose-up` then `GET /health` and `GET /health/ready` succeed.
5. `make compose-down` then `make compose-up-persistent`; restart keeps a
   runtime entry; soft reset restores baseline.
6. `make test-integration` (real 389 DS) and `make test-integration-native`.
7. `make test-e2e` (mock by default; set `LABLDAP_E2E_BASE_URL` for live UI).
8. `make scan` has no unapproved criticals.
9. `dist/sbom/source.cdx.json` names the pinned dirsrv digest.
10. `dist/release/provenance.json` matches `git rev-parse HEAD`.
11. `dist/release/SHA256SUMS` covers OpenAPI, Compose, and digest pins.
12. Release notes list versions, platforms, limitations, migration.
13. Operator guide has no undocumented `dsconf` steps.
14. Examples still compile and contain only `lab-fixture-*` placeholders.
15. Advertised architectures still match `deploy/docker/architectures.md`.
16. Tag annotated: `git tag -a vX.Y.Z -m "LabLDAP vX.Y.Z"`.
17. Do **not** `docker push`. Confirm `LICENSE` remains the MIT text.
