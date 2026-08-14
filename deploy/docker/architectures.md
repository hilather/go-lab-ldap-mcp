# Supported image architectures

Recorded: 2026-08-14  
Task: T-116  
Decision: OD-005

## Advertised (tested) architectures

Release files and operator docs may claim only:

- linux/amd64

That is the architecture smoke-tested with `make image` / `make image-bootstrap` on this host.

## Upstream pin observation

`docker manifest inspect` of the pinned `deploy/docker/dirsrv.digest` reports
`linux/amd64`, `linux/arm64`, `linux/ppc64le`, and `linux/s390x`.

`linux/arm64` is **not advertised**. An arm64 control/bootstrap smoke was not
run in this environment (no arm64 runner / qemu build). `ppc64le` and
`s390x` are out of scope (OD-005).

`make image-multiarch` builds `linux/amd64` by default. Set
`LABLDAP_PLATFORMS=linux/amd64,linux/arm64` only after an arm64 smoke
passes and this file is updated.

## Contract versions

`labldap-control:dev` and `labldap-bootstrap:dev` must report the same
`version=` field (`make image` already compares them when both tags exist).
`tools/archcheck` fails if an advertised platform is missing from the
pinned dirsrv digest.
