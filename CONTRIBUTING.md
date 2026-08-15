# Contributing

Thanks for looking under the hood. Read the [README](README.md) and the
[user](docs/guides/user-guide.md) / [deploy](docs/guides/deploy.md) guides
before changing behaviour a lab operator will feel.

Accepted architecture decision records outrank other documents. Title-only
stubs in `docs/adr/*.stub.md` are placeholders, not decisions.

## Architecture

These are the lines the project does not cross:

- Do not implement an LDAP listener or BER engine in Go. 389 DS is the
  directory.
- Do not store users, groups, or memberships in an application-only map.
- Do not mount `/var/run/docker.sock` into any application container.
- Do not give Directory Manager to the long-running `labldap` process.
  DM is bootstrap-only (`labldap-bootstrap`).
- REST and MCP do not call each other. Both call the same application
  services.
- Do not commit secrets. Lab files live in untracked `secrets/`.

## Verify

Toolchain pins: [docs/toolchain.md](docs/toolchain.md).

```text
make verify
```

That is the release gate: format, lint, generate, generate-drift, unit
tests, security scans, SBOM, checksums, architecture check.

Other targets you will actually run:

```text
make test-integration    # real 389 DS, needs Docker
make test-e2e
make image && make image-bootstrap
make compose-up
```

Security, secret, and license policy:
[docs/security/dependency-policy.md](docs/security/dependency-policy.md).

## Generated files

[`api/openapi.yaml`](api/openapi.yaml) is the OpenAPI source.
`api/generated/` is not hand-edited. Change the spec, run `make generate`,
confirm with `make generate-drift`. See
[docs/generated-files.md](docs/generated-files.md).

## Public contracts

If you change configuration, REST, or MCP, document and test it in the
same change.

- New config fields need defaults, validation, schema, an example, and a
  compatibility note.
- New REST operations belong in OpenAPI and the generated clients.
- New MCP tools need input/output schema, scopes, annotations, and tests.

Breaking config → new `apiVersion`. Breaking REST → new URL version.
Breaking MCP → new tool name, or a documented transition.

If the implementation forces a design change, write an ADR from
[docs/adr/template.md](docs/adr/template.md) before you change the
contract.

## Pull requests

Use the repository checklist. Do not commit secrets. Keep `make verify`
green. Say what you ran, what is still untested, and anything that
touches credentials, reset, export, or browser state.

Agent contributors follow [AGENTS.md](AGENTS.md). Humans can ignore the
machine report format and write a normal PR description.
