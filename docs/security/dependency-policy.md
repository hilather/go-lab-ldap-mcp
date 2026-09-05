# Dependency and vulnerability policy

## Critical findings

CI (`make test-security`) fails the build when:

- `govulncheck` reports a vulnerability in a reachable package of this module, or
- the secret scanner finds a high-confidence credential pattern in tracked source, or
- a Go module path or version string contains a denylist token
  (AGPL / SSPL / BUSL; see `tools/licensecheck`). This is a path-token
  scan, not a full `go-licenses` attribution pass.

Unapproved **critical** findings block merge. Exceptions require a dated note in this file naming the finding, the reason, and the expiry.

## Secret scanning

The scanner in `tools/secretscan` looks for high-confidence patterns (PEM private keys, GitHub tokens, AWS access keys, Slack tokens). It does not print matched secret values — only file path, line, and rule ID.

Do not commit Directory Manager passwords, API tokens, or session material. Lab secrets live in untracked `/secrets/` files.

## License denylist

The project is MIT-licensed (OD-003 resolved). Do not add dependencies whose license is AGPL-3.0, SSPL, or another copyleft network-use license. Allowed: MIT, BSD, Apache-2.0, ISC, MPL-2.0, Unlicense, and the Go standard library.

## Container scanning and SBOM (T-118)

`make sbom` writes a CycloneDX source SBOM to `dist/sbom/source.cdx.json`.
It names the pinned 389 DS digest (`deploy/docker/dirsrv.digest`) and the
Go / frontend module graph. When `syft` is on PATH, operators may also
run `syft labldap-control:dev -o cyclonedx-json` for an image SBOM; that
step is optional and not required for `make verify`.

`make scan` (`tools/imagescan`) fails the release gate on unapproved
**critical** findings:

- `govulncheck` (same pin as `make test-security`)
- `grype` against `labldap-control:dev` and `labldap-bootstrap:dev` when
  both the tool and the local images exist

`make checksums` writes `dist/release/provenance.json` (source revision +
image IDs + workflow path) and `dist/release/SHA256SUMS`. Signing
(`cosign`) is optional and is not performed here (OD-004: do not push).

## Approved exceptions

| ID | Reason | Expires |
| --- | --- | --- |
| GO-2026-6090 | Pinned toolchain `go1.26.5` (`crypto/tls` handshake limit). Fixed in `go1.26.6`. Do not bump the builder digest in this PR without a new pin. | 2026-09-14 |
| GO-2026-6089 | Pinned toolchain `go1.26.5` (`net/http` ReadHeaderTimeout on h2c). Fixed in `go1.26.6`. | 2026-09-14 |
| GO-2026-5972 | Pinned toolchain `go1.26.5` (`encoding/asn1` recursion). Fixed in `go1.26.6`. | 2026-09-14 |
| GO-2026-6218 | Pinned toolchain `go1.26.5` (`net/url` quadratic `..` resolution). Fixed in `go1.26.6`. | 2026-09-14 |
| GO-2026-5026 | Pinned toolchain `go1.26.5` (`net/http` IDNA Punycode). Fixed in `go1.26.6`. Module `golang.org/x/net` is already `v0.57.0` (≥ `v0.55.0`). | 2026-09-14 |
