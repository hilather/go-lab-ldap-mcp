# LabLDAP task runner. Tool versions are pinned; do not use @latest.

GO               ?= go
PNPM             ?= pnpm
export GOTOOLCHAIN ?= go1.26.5
export GOPROXY    ?= https://proxy.golang.org,direct

GOVULNCHECK_MOD  := golang.org/x/vuln/cmd/govulncheck@v1.1.4
OAPI_CODEGEN_MOD := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
OPENAPI_TS_PKG   := openapi-typescript@7.13.0

DIRSRV_IMAGE     := $(shell cat deploy/docker/dirsrv.digest)
GO_IMAGE         := $(shell cat deploy/docker/golang.digest)
NODE_IMAGE       := $(shell cat deploy/docker/node.digest)
ALPINE_IMAGE     := $(shell cat deploy/docker/alpine.digest)
COMPOSE_EPHEMERAL  := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.ephemeral.yaml -p labldap
COMPOSE_PERSISTENT := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.persistent.yaml -p labldap
COMPOSE            := $(COMPOSE_EPHEMERAL)
COMPOSE_ENV        := secrets/directory.env
COMPOSE_DM         := secrets/dm.pw
COMPOSE_TLS        := secrets/tls

VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
REVISION         ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')
BUILT_AT         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_LDFLAGS    := -s -w -X github.com/hilather/go-lab-ldap-mcp/internal/observability.version=$(VERSION) -X github.com/hilather/go-lab-ldap-mcp/internal/observability.revision=$(REVISION) -X github.com/hilather/go-lab-ldap-mcp/internal/observability.builtAt=$(BUILT_AT)
IMAGE_BUILD_ARGS := --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) --build-arg BUILT_AT=$(BUILT_AT)

.PHONY: help format lint generate generate-drift test test-unit \
	test-integration test-e2e test-security compose-up compose-down \
	compose-up-persistent compose-reset compose-secrets compose-preflight \
	setup-tls image image-bootstrap \
	image-control-placeholder verify frontend-install frontend-build

help:
	@printf '%s\n' \
		'LabLDAP Make targets (versions: see docs/toolchain.md)' \
		'  format             go fmt ./...' \
		'  lint               go vet + frontend pin lint' \
		'  generate           regenerate OpenAPI Go and TypeScript artifacts' \
		'  generate-drift     fail if generate would change the tree' \
		'  test               alias for test-unit' \
		'  test-unit          Go tests + frontend build/scaffold tests' \
		'  test-integration   real 389 DS harness (pinned digest; needs Docker)' \
		'  test-e2e           Playwright UI suite (mock control plane; optional live URL)' \
		'  test-security      secret scan, govulncheck, license denylist' \
		'  compose-up         ephemeral tmpfs /data; directory → TLS import → bootstrap → control' \
		'  compose-up-persistent  named volume /data (restart keeps runtime entries)' \
		'  compose-down       stop the Compose project' \
		'  compose-reset      operator hard reset: down -v then compose-up (not REST/MCP)' \
		'  image-bootstrap    build labldap-bootstrap:dev (pinned 389 DS)' \
		'  image              build labldap-control:dev (hardened; matching version)' \
		'  verify             format lint generate generate-drift test-unit test-security'

format:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	cd frontend && $(PNPM) lint

generate:
	@mkdir -p api/generated/typescript
	$(GO) run $(OAPI_CODEGEN_MOD) -config api/oapi-codegen.yaml api/openapi.yaml
	cd frontend && $(PNPM) dlx --package $(OPENAPI_TS_PKG) openapi-typescript ../api/openapi.yaml -o ../api/generated/typescript/schema.d.ts

generate-drift: generate
	$(GO) run ./tools/gencheck

test: test-unit

test-unit: frontend-install
	$(GO) test ./...
	cd frontend && $(PNPM) test

test-integration:
	$(GO) test -tags=integration ./test/integration/... -count=1 -timeout 25m

test-e2e: frontend-build
	cd test/e2e && $(PNPM) install --frozen-lockfile
	cd test/e2e && $(PNPM) exec playwright install chromium
	cd test/e2e && $(PNPM) test
	@printf '%s\n' 'test-e2e: default target is the contract mock. Set LABLDAP_E2E_BASE_URL for a live Compose/389 DS stack (T-042 residual).'

test-security:
	$(GO) run ./tools/secretscan .
	$(GO) run $(GOVULNCHECK_MOD) ./...
	$(GO) run ./tools/licensecheck

compose-preflight:
	$(GO) run ./tools/composepreflight

compose-secrets:
	$(GO) run ./tools/setupsecrets --dir secrets

setup-tls:
	$(GO) run ./tools/setuptls generate --dir $(COMPOSE_TLS) --host directory

compose-up: image image-bootstrap compose-preflight compose-secrets setup-tls
	$(COMPOSE) up -d --wait --remove-orphans directory
	$(GO) run ./tools/setuptls publish --out $(COMPOSE_TLS)/ca.crt --project labldap \
		-f deploy/compose/compose.yaml -f deploy/compose/compose.ephemeral.yaml
	$(COMPOSE) up -d --wait --remove-orphans

compose-up-persistent: image image-bootstrap compose-preflight compose-secrets setup-tls
	$(COMPOSE_PERSISTENT) up -d --wait --remove-orphans directory
	$(GO) run ./tools/setuptls import --dir $(COMPOSE_TLS) --project labldap \
		-f deploy/compose/compose.yaml -f deploy/compose/compose.persistent.yaml
	$(COMPOSE_PERSISTENT) up -d --wait --remove-orphans

compose-down:
	-$(COMPOSE) down --remove-orphans
	-$(COMPOSE_PERSISTENT) down --remove-orphans

compose-reset:
	-$(COMPOSE) down --remove-orphans -v
	-$(COMPOSE_PERSISTENT) down --remove-orphans -v
	$(MAKE) compose-up

image-bootstrap:
	docker build \
		-f deploy/docker/Dockerfile.bootstrap \
		--build-arg DIRSRV_IMAGE=$(DIRSRV_IMAGE) \
		--build-arg GO_IMAGE=$(GO_IMAGE) \
		$(IMAGE_BUILD_ARGS) \
		-t labldap-bootstrap:dev \
		.
	@docker run --rm --entrypoint dsconf labldap-bootstrap:dev --help >/dev/null
	@docker run --rm --entrypoint dsctl labldap-bootstrap:dev --help >/dev/null
	@docker run --rm labldap-bootstrap:dev version >/dev/null
	@printf '%s\n' 'image-bootstrap: labldap-bootstrap:dev version=$(VERSION)'

image-control-placeholder:
	docker build \
		-f deploy/docker/Dockerfile.control-placeholder \
		-t labldap-control:placeholder \
		.

image:
	docker build \
		-f deploy/docker/Dockerfile.control \
		--build-arg GO_IMAGE=$(GO_IMAGE) \
		--build-arg NODE_IMAGE=$(NODE_IMAGE) \
		--build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) \
		$(IMAGE_BUILD_ARGS) \
		-t labldap-control:dev \
		.
	@cver=$$(docker run --rm labldap-control:dev version); \
	printf '%s\n' "$$cver"; \
	if docker image inspect labldap-bootstrap:dev >/dev/null 2>&1; then \
		bver=$$(docker run --rm labldap-bootstrap:dev version); \
		cfield=$$(printf '%s\n' "$$cver" | sed -n 's/.*version=//p' | awk '{print $$1}'); \
		bfield=$$(printf '%s\n' "$$bver" | sed -n 's/.*version=//p' | awk '{print $$1}'); \
		if [ "$$cfield" != "$$bfield" ]; then \
			printf '%s\n' "image: version mismatch control=$$cfield bootstrap=$$bfield"; \
			exit 1; \
		fi; \
	fi
	@cid=$$(docker run -d --read-only --cap-drop=ALL --security-opt no-new-privileges:true \
		--tmpfs /tmp:uid=65532,gid=65532,mode=1777,size=16m \
		-e LABLDAP_LISTEN=127.0.0.1:8443 \
		labldap-control:dev serve --placeholder); \
	ok=0; \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do \
		if docker exec "$$cid" wget -q -O - http://127.0.0.1:8443/health >/dev/null 2>&1; then ok=1; break; fi; \
		sleep 0.4; \
	done; \
	docker rm -f "$$cid" >/dev/null; \
	if [ "$$ok" != 1 ]; then printf '%s\n' 'image: hardened /health smoke failed'; exit 1; fi
	@printf '%s\n' 'image: labldap-control:dev version=$(VERSION)'

frontend-install:
	cd frontend && $(PNPM) install --frozen-lockfile

frontend-build: frontend-install
	cd frontend && $(PNPM) build

verify: format lint generate generate-drift test-unit test-security
	@printf '%s\n' 'verify: ok'
