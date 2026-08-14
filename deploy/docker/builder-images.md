# Pinned builder and runtime base images

Recorded: 2026-08-14 for T-108 / T-109. Release files must use these digest pins, never a floating tag alone.

| Role | Pin file | Reference |
| --- | --- | --- |
| Go builder | `deploy/docker/golang.digest` | `golang:1.26.5` (toolchain `go1.26.5`) |
| Frontend builder | `deploy/docker/node.digest` | `node:22.14.0-bookworm` (OD-010; `pnpm@10.14.0`) |
| Control runtime | `deploy/docker/alpine.digest` | `alpine:3.21` (`ca-certificates`, `wget`) |
| 389 DS / bootstrap base | `deploy/docker/dirsrv.digest` | official `quay.io/389ds/dirsrv` (OD-006) |

Architecture advertised for release: `linux/amd64` only. The pinned dirsrv
digest is a multi-arch list that includes `linux/arm64`, but arm64 is not
advertised until an arm64 smoke runs. See `deploy/docker/architectures.md`.
