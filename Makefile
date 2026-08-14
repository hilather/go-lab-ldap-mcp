# LabLDAP task runner. Tool versions are pinned; do not use @latest.

GO               ?= go
PNPM             ?= pnpm
export GOTOOLCHAIN ?= go1.26.5
export GOPROXY    ?= https://proxy.golang.org,direct

GOVULNCHECK_MOD  := golang.org/x/vuln/cmd/govulncheck@v1.1.4

DIRSRV_IMAGE     := $(shell cat deploy/docker/dirsrv.digest)
COMPOSE          := docker compose -f deploy/compose/compose.yaml -p labldap
COMPOSE_ENV      := secrets/directory.env
COMPOSE_DM       := secrets/dm.pw

.PHONY: help format lint generate generate-drift test test-unit \
	test-integration test-e2e test-security compose-up compose-down \
	compose-reset compose-secrets image image-bootstrap \
	image-control-placeholder verify frontend-install frontend-build

help:
	@printf '%s\n' \
		'LabLDAP Make targets (versions: see docs/toolchain.md)' \
		'  format             go fmt ./...' \
		'  lint               go vet + frontend pin lint' \
		'  generate           regenerate committed artifacts (none in M0)' \
		'  generate-drift     fail if generate would change the tree' \
		'  test               alias for test-unit' \
		'  test-unit          Go tests + frontend placeholder tests' \
		'  test-integration   real 389 DS harness (pinned digest; needs Docker)' \
		'  test-e2e           pending T-107 (Playwright)' \
		'  test-security      secret scan, govulncheck, license denylist' \
		'  compose-up         directory → bootstrap → placeholder control' \
		'  compose-down       stop the T-042 Compose project' \
		'  compose-reset      pending T-110 (operator full engine reset)' \
		'  image-bootstrap    build labldap-bootstrap:dev (pinned 389 DS)' \
		'  image              pending T-108 (hardened control image)' \
		'  verify             format lint generate generate-drift test-unit test-security'

format:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	cd frontend && $(PNPM) lint

generate:
	@printf '%s\n' 'generate: no generated sources in M0 (OpenAPI lands in T-060)'

generate-drift: generate
	$(GO) run ./tools/gencheck

test: test-unit

test-unit:
	$(GO) test ./...
	cd frontend && $(PNPM) test

test-integration:
	$(GO) test -tags=integration ./test/integration/... -count=1 -timeout 25m

test-e2e:
	@printf '%s\n' 'test-e2e: pending T-107 — Playwright suite not in this milestone'
	@printf '%s\n' 'PENDING:test-e2e'

test-security:
	$(GO) run ./tools/secretscan .
	$(GO) run $(GOVULNCHECK_MOD) ./...
	$(GO) run ./tools/licensecheck

compose-secrets:
	@mkdir -p secrets
	@if [ ! -f $(COMPOSE_ENV) ]; then \
		umask 077; \
		pw=$$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n'); \
		printf 'DS_DM_PASSWORD=%s\n' "$$pw" > $(COMPOSE_ENV); \
		printf '%s\n' "$$pw" > $(COMPOSE_DM); \
		chmod 0600 $(COMPOSE_ENV) $(COMPOSE_DM); \
	fi
	@if [ ! -f $(COMPOSE_DM) ]; then \
		umask 077; \
		sed -n 's/^DS_DM_PASSWORD=//p' $(COMPOSE_ENV) > $(COMPOSE_DM); \
		chmod 0600 $(COMPOSE_DM); \
	fi

compose-up: image-bootstrap image-control-placeholder compose-secrets
	$(COMPOSE) up -d --wait --remove-orphans

compose-down:
	$(COMPOSE) down --remove-orphans

compose-reset:
	@printf '%s\n' 'compose-reset: pending T-110 — operator full engine reset (not REST/MCP)'
	@printf '%s\n' 'PENDING:compose-reset'

image-bootstrap:
	docker build \
		-f deploy/docker/Dockerfile.bootstrap \
		--build-arg DIRSRV_IMAGE=$(DIRSRV_IMAGE) \
		-t labldap-bootstrap:dev \
		.
	@docker run --rm --entrypoint dsconf labldap-bootstrap:dev --help >/dev/null
	@docker run --rm labldap-bootstrap:dev version >/dev/null
	@printf '%s\n' 'image-bootstrap: labldap-bootstrap:dev'

image-control-placeholder:
	docker build \
		-f deploy/docker/Dockerfile.control-placeholder \
		-t labldap-control:placeholder \
		.

image:
	@printf '%s\n' 'image: pending T-108 — hardened control image not in this milestone'
	@printf '%s\n' 'PENDING:control-image'

frontend-install:
	cd frontend && $(PNPM) install --frozen-lockfile

frontend-build: frontend-install
	cd frontend && $(PNPM) build

verify: format lint generate generate-drift test-unit test-security
	@printf '%s\n' 'verify: ok'
