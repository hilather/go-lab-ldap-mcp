# Package Manifest

Generated: 2026-08-12

## Package summary

- Markdown documents excluding this manifest: 25.
- Total lines excluding this manifest: 7519.
- Implementation backlog: 120 sequential tasks (`T-001` through `T-120`).
- Architecture decisions: 7 accepted ADRs.
- Integrity algorithm: SHA-256 over the exact UTF-8 file bytes.

## File inventory

| Path | Lines | SHA-256 | Purpose |
| --- | ---: | --- | --- |
| [`AGENTS.md`](AGENTS.md) | 238 | `56ca19588520d47dc2b21c1b2983b09a59fcceca690c0074fb68c76e27b9627d` | Binding implementation rules, boundaries, workflow, coding standards, tests, and definition of done. |
| [`AGENT_PROMPT.md`](AGENT_PROMPT.md) | 85 | `eb6a5d84b85262c36d806879da3c9cae16e4e73d770cb255259b93b0215ecced` | Copy-paste prompt for an autonomous coding agent to execute the backlog safely. |
| [`README.md`](README.md) | 135 | `5afb4833acb56b9787f39619b98b26467973992c8ec5dcd680a49908b0ddcb15` | Package entry point, selected architecture, document map, and first-release definition. |
| [`TASKS.md`](TASKS.md) | 1378 | `6f50a5575d4c6d86067525ca4e7e12f8c94f0713bb60ef7091910b933aaa1a64` | Ordered issue-ready backlog with 120 tasks, dependencies, deliverables, and acceptance checklists. |
| [`docs/00-product-requirements.md`](docs/00-product-requirements.md) | 291 | `af2c14ff06e8a9112aa228caadff2a71bde94dab5a364e2a763610fd6b39579f` | Scope, actors, use cases, functional and non-functional requirements, and release acceptance. |
| [`docs/01-system-architecture.md`](docs/01-system-architecture.md) | 480 | `64462fe31db101f10ad553c96b21dae933782d6b40d2c4ca50edb42c2d847653` | System context, containers, components, trust boundaries, sequences, state, and failure modes. |
| [`docs/02-configuration-and-domain-model.md`](docs/02-configuration-and-domain-model.md) | 813 | `294c2c1cad5608c22c38a240e4c68a89aed56e5f7dfa8afec447f69554502376` | Versioned YAML model, validation, normalization, revision hashing, reconciliation, identity, groups, ACL DSL, and examples. |
| [`docs/03-389ds-engine-adapter.md`](docs/03-389ds-engine-adapter.md) | 510 | `e2849e85ed1d4f1aefcd56614853c82a1044c539af86999cf447003ceeae801e` | 389 DS topology, bootstrap, TLS, plugins, policies, ACIs, service account, reset, export, and capability detection. |
| [`docs/04-rest-api.md`](docs/04-rest-api.md) | 544 | `13265167d4056048f9120113bab8040e80ae3b0601fc90cd2b6d448b3b5f7823` | REST contract, resources, errors, concurrency, pagination, authorization, and OpenAPI workflow. |
| [`docs/05-mcp-api.md`](docs/05-mcp-api.md) | 465 | `69b74b15f6876037a8e751010f4232b57bc70963e8203a048257ee9b642f7a15` | MCP transport, tools, resources, scopes, schemas, errors, annotations, and conformance. |
| [`docs/06-security-and-threat-model.md`](docs/06-security-and-threat-model.md) | 436 | `b64d73515b39c0ed4359811694d675e0654aaa8b9b64a089b4ee75fb3458277d` | Assets, actors, trust zones, threats, mitigations, token/session design, secrets, TLS, logging, and hardening. |
| [`docs/07-web-ui.md`](docs/07-web-ui.md) | 491 | `a8bdbe0d7ed12b9b8ec51d865f1c5097deba20d78fc84d7265a62f2cc601b5c3` | Routes, workflows, components, state, accessibility, validation, security, and frontend tests. |
| [`docs/08-deployment-and-operations.md`](docs/08-deployment-and-operations.md) | 482 | `529425ded5c238e5673d827c6bf4cc3c5ca2fdb1d089abdb7a24a65810be9968` | Images, Compose topology, ephemeral/persistent storage, secrets, health, backup/export, and operations. |
| [`docs/09-testing-and-quality.md`](docs/09-testing-and-quality.md) | 414 | `c48e3e8cf47f04413cd6a75b629f681d7f84c356a1d2f8f85daaa2fb86466998` | Static, unit, integration, contract, MCP, browser, compatibility, performance, security, and release testing. |
| [`docs/10-implementation-plan.md`](docs/10-implementation-plan.md) | 363 | `28e709e93ccafe98864aeca7e2baeba34f189ff793d21231ce98156dd41d20c7` | Milestones, critical path, parallelization, checkpoints, gates, and completion criteria. |
| [`docs/11-risk-register.md`](docs/11-risk-register.md) | 71 | `fec063dc9060b905cfedbc283e56676fc597488597f9797e794fd54c7112d789` | Technical, security, compatibility, and delivery risks with mitigations and escalation triggers. |
| [`docs/12-traceability-matrix.md`](docs/12-traceability-matrix.md) | 83 | `9e12422887ad049f2619c30f962f0f79a1569cf8da27f36cfdb2aa35e67a2596` | Requirements mapped to architecture, backlog tasks, and verification evidence. |
| [`docs/13-open-decisions.md`](docs/13-open-decisions.md) | 80 | `dd436ef1fba13e9d939da868cfb72fc3d4e0fa2616bb633725c482eaad204aff` | Owner decisions, upstream verification points, agent defaults, and ADR triggers. |
| [`docs/adr/0001-use-go-control-plane-with-389ds.md`](docs/adr/0001-use-go-control-plane-with-389ds.md) | 34 | `56a79517ea858443acdcc3c0bc70cb29765e7df3d8516732f23fc56f25b0cf5b` | Decision to use Go around 389 Directory Server rather than implement LDAP. |
| [`docs/adr/0002-389ds-is-the-single-source-of-truth.md`](docs/adr/0002-389ds-is-the-single-source-of-truth.md) | 20 | `8d9135bddf43a994fe0b6564e1a50a4a977b7d8b467291a0a593b41efd3fb0e5` | Decision that all directory data and runtime changes live in 389 DS. |
| [`docs/adr/0003-separate-bootstrap-and-runtime-privileges.md`](docs/adr/0003-separate-bootstrap-and-runtime-privileges.md) | 22 | `d5ff3f7abd44858513f4c003a689ac382cac3b21bedb39d73d52edf73864f752` | Decision to isolate Directory Manager bootstrap privileges from runtime. |
| [`docs/adr/0004-versioned-declarative-configuration-and-reconciliation.md`](docs/adr/0004-versioned-declarative-configuration-and-reconciliation.md) | 21 | `4106ef6c02bf80f7ecddadff4e0254273ad45a32fbe34199623e78c31455a0e4` | Decision for versioned configuration, deterministic compilation, and reconciliation. |
| [`docs/adr/0005-static-bearer-token-as-explicit-lab-mode.md`](docs/adr/0005-static-bearer-token-as-explicit-lab-mode.md) | 21 | `7077d6a7ced8e5cba9f5be40cfb40d8f210938f4feb20c67f8096e768f3c1a90` | Decision to support scoped static bearer tokens as an explicit lab authorization mode. |
| [`docs/adr/0006-rest-and-mcp-share-application-services.md`](docs/adr/0006-rest-and-mcp-share-application-services.md) | 21 | `2eee732f206f87a7480f6ab9c89e4e279ba79054115a9594b06d9c42afd1c556` | Decision for transport-neutral use cases and one authorization implementation. |
| [`docs/adr/0007-soft-reset-not-container-control.md`](docs/adr/0007-soft-reset-not-container-control.md) | 21 | `b0f80b125780b65c36ca751c306a6441df9999852e735311824bc2cb763c9e87` | Decision to expose suffix-scoped reset without container-runtime privileges. |

## Validation performed

- Every Markdown file ends with a newline.
- Fenced code blocks are balanced.
- Relative Markdown links resolve inside the package.
- Task IDs are sequential from `T-001` through `T-120` with no duplicates.
- Every explicit task dependency references an existing task ID.

The ZIP checksum is published alongside the downloadable archive rather than embedded here, because adding it to this package would change the archive bytes.
