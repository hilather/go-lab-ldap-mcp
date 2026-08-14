# Measured limits (T-117)

Architecture §14 reference profile: **one** control replica, **one** 389 DS
instance, up to approximately **10,000 users** and **1,000 groups**,
paginated lists, bounded pool and exports. This is not an HA promise.

## How measurements are produced

```text
go run ./tools/dataset --users 50 --groups 5 --out /tmp/soak-small.yaml
go test -tags=integration ./test/integration/dirsrv -run Soak -count=1 -timeout 25m
# optional medium profile (long):
LABLDAP_SOAK_MEDIUM=1 go test -tags=integration ./test/integration/dirsrv -run SoakMedium -count=1 -timeout 60m
```

`tools/dataset` writes YAML with `passwordFile` references only.

## Recorded on 2026-08-14 (linux/amd64)

| Profile | Users | Groups | First-page list | Soak | Result |
| --- | ---: | ---: | --- | --- | --- |
| Small (CI default) | ~20 extra + seed | 1 seed | **not recorded** (live `TestSoakSmallProfile` not run here) | 8 workers × 400ms pool `Ping` (short leak probe) | residual: no first-page / reset / export / membership numbers |
| Medium (§14) | 10_000 | 1_000 | **not measured in this environment** | generator + compile only (`LABLDAP_SOAK_MEDIUM=1`) | residual: medium bootstrap/list was not run |

Unit evidence already landed with T-047: `internal/directory/ldapclient.TestPoolShortLeak`.

## Documented operational bounds (compiled defaults)

These are **configuration limits**, not benchmark claims:

| Limit | Default (`example-lab.yaml`) |
| --- | --- |
| `pageSizeDefault` / `pageSizeMax` | 50 / 500 |
| `searchSizeLimit` | 1000 |
| `exportMaxEntries` / `exportMaxBytes` | 20_000 / 64MiB |
| `ldapPoolSize` | 16 |
| `concurrentMutations` | 8 |
| Directory / control Compose guidance | 512Mi + 1 CPU / 256Mi |

If a medium-profile first-page or soak measurement is later recorded, replace
the residual row above with the measured numbers. Do not treat the §14
profile as a guaranteed SLA.
