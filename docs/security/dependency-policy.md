# Dependency and vulnerability policy

## Critical findings

CI (`make test-security`) fails the build when:

- `govulncheck` reports a vulnerability in a reachable package of this module, or
- the secret scanner finds a high-confidence credential pattern in tracked source, or
- a Go module path matches the license denylist below.

Unapproved **critical** findings block merge. Exceptions require a dated note in this file naming the finding, the reason, and the expiry.

## Secret scanning

The scanner in `tools/secretscan` looks for high-confidence patterns (PEM private keys, GitHub tokens, AWS access keys, Slack tokens). It does not print matched secret values — only file path, line, and rule ID.

Do not commit Directory Manager passwords, API tokens, or session material. Lab secrets live in untracked `/secrets/` files.

## License denylist

The first release is privately owned (OD-003). Do not add dependencies whose license is AGPL-3.0, SSPL, or another copyleft network-use license. Allowed: MIT, BSD, Apache-2.0, ISC, MPL-2.0, Unlicense, and the Go standard library.

## Container scanning

Image scans / SBOM land with T-118. `make image` builds the hardened
`labldap-control:dev` image (T-108) from pinned builder digests.
