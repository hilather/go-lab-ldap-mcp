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
LABLDAPD_BASE    := $(shell cat deploy/docker/labldapd.digest)
COMPOSE_EPHEMERAL  := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.ephemeral.yaml -p labldap
COMPOSE_PERSISTENT := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.persistent.yaml -p labldap
COMPOSE            := $(COMPOSE_EPHEMERAL)
COMPOSE_NATIVE_EPHEMERAL  := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.native.yaml -f deploy/compose/compose.native-ephemeral.yaml -p labldap
COMPOSE_NATIVE_PERSISTENT := docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.native.yaml -f deploy/compose/compose.native-persistent.yaml -p labldap
COMPOSE_NATIVE            := $(COMPOSE_NATIVE_EPHEMERAL)
COMPOSE_NATIVE_SCENARIO            := deploy/compose/scenario.native.yaml
COMPOSE_NATIVE_PERSISTENT_SCENARIO := deploy/compose/scenario.native-persistent.yaml
COMPOSE_ENV        := secrets/directory.env
COMPOSE_DM         := secrets/dm.pw
COMPOSE_TLS        := secrets/tls

VERSION          ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
REVISION         ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || printf 'unknown')
BUILT_AT         ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
IMAGE_LDFLAGS    := -s -w -X github.com/hilather/go-lab-ldap-mcp/internal/observability.version=$(VERSION) -X github.com/hilather/go-lab-ldap-mcp/internal/observability.revision=$(REVISION) -X github.com/hilather/go-lab-ldap-mcp/internal/observability.builtAt=$(BUILT_AT)
IMAGE_BUILD_ARGS := --build-arg VERSION=$(VERSION) --build-arg REVISION=$(REVISION) --build-arg BUILT_AT=$(BUILT_AT)

.PHONY: help format lint generate generate-drift test test-unit \
	test-integration test-integration-native test-e2e test-security compose-up compose-down \
	compose-up-persistent compose-reset compose-secrets compose-preflight \
	compose-up-native compose-up-native-persistent compose-down-native \
	compose-reset-native \
	setup-tls image image-bootstrap image-multiarch image-native \
	image-control-placeholder verify frontend-install frontend-build \
	sbom scan checksums archcheck dataset

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
		'  test-integration-native  T-148 native engine variant (in-process labldapd; no Docker)' \
		'  test-e2e           Playwright UI suite (mock control plane; optional live URL)' \
		'  test-security      secret scan, govulncheck, license denylist' \
		'  compose-up         ephemeral tmpfs /data; publish instance CA; bootstrap → control' \
		'  compose-up-persistent  named volume /data; dsctl tls import lab CA' \
		'  compose-down       stop the Compose project' \
		'  compose-reset      operator hard reset: down -v then compose-up (not REST/MCP)' \
		'  compose-up-native  native labldapd engine: directory → bootstrap → control (needs T-143/T-144/T-146 at runtime)' \
		'  compose-up-native-persistent  native engine with named-volume /data' \
		'  compose-down-native   stop the native Compose stack' \
		'  compose-reset-native  operator hard reset: down -v then compose-up-native (not REST/MCP)' \
		'  image-native       build labldapd:dev (native engine; pinned bases)' \
		'  image-bootstrap    build labldap-bootstrap:dev (pinned 389 DS)' \
		'  image              build labldap-control:dev (hardened; matching version)' \
		'  image-multiarch    build advertised platforms only (see deploy/docker/architectures.md)' \
		'  sbom               write source CycloneDX SBOM to dist/sbom/' \
		'  scan               govulncheck + optional grype; fail on unapproved criticals' \
		'  checksums          provenance.json + SHA256SUMS in dist/release/' \
		'  archcheck          compare advertised arches to the pinned dirsrv digest' \
		'  verify             format lint generate generate-drift test-unit test-security sbom checksums archcheck'

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
	$(GO) test -tags=integration ./test/integration/... -count=1 -timeout 30m

# T-148: same integration suite against the native engine. The T-115 client
# matrix runs against an in-process labldapd-equivalent fixture (no Docker
# needed); 389-only tests skip with their parity-contract Delta/Excluded ID
# (skip ledger: test/integration/dirsrv/engine.go).
test-integration-native:
	LABLDAP_IT_ENGINE=native $(GO) test -tags=integration ./test/integration/... -count=1 -timeout 30m

test-e2e: frontend-build
	cd test/e2e && $(PNPM) install --frozen-lockfile
	cd test/e2e && $(PNPM) exec playwright install chromium
	cd test/e2e && $(PNPM) test
	@printf '%s\n' 'test-e2e: default target is the contract mock. Set LABLDAP_E2E_BASE_URL for a live Compose/389 DS stack (T-042 residual).'

test-security:
	$(GO) run ./tools/secretscan .
	$(GO) run ./tools/imagescan
	$(GO) run ./tools/licensecheck

compose-preflight:
	$(GO) run ./tools/composepreflight

compose-secrets:
	$(GO) run ./tools/setupsecrets --dir secrets

setup-tls:
	$(GO) run ./tools/setuptls generate --dir $(COMPOSE_TLS) --host directory

compose-up: image image-bootstrap compose-preflight compose-secrets setup-tls
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/instance-ca.crt $(COMPOSE) up -d --wait --remove-orphans directory
	$(GO) run ./tools/setuptls publish --out $(COMPOSE_TLS)/instance-ca.crt --project labldap \
		-f deploy/compose/compose.yaml -f deploy/compose/compose.ephemeral.yaml
	# Recreate secret-prep so setupsecrets --force copies into control-secrets.
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/instance-ca.crt $(COMPOSE) up -d --no-deps --force-recreate secret-prep
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/instance-ca.crt $(COMPOSE) wait secret-prep
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/instance-ca.crt $(COMPOSE) up -d --wait --remove-orphans --force-recreate control

compose-up-persistent: image image-bootstrap compose-preflight compose-secrets setup-tls
	LABLDAP_SCENARIO_FILE=deploy/compose/scenario.persistent.yaml \
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_PERSISTENT) up -d --wait --remove-orphans directory
	$(GO) run ./tools/setuptls import --dir $(COMPOSE_TLS) --project labldap \
		-f deploy/compose/compose.yaml -f deploy/compose/compose.persistent.yaml
	LABLDAP_SCENARIO_FILE=deploy/compose/scenario.persistent.yaml \
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_PERSISTENT) up -d --no-deps --force-recreate secret-prep
	LABLDAP_SCENARIO_FILE=deploy/compose/scenario.persistent.yaml \
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_PERSISTENT) wait secret-prep
	LABLDAP_SCENARIO_FILE=deploy/compose/scenario.persistent.yaml \
	LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_PERSISTENT) up -d --wait --remove-orphans --force-recreate control

compose-down:
	-$(COMPOSE) down --remove-orphans
	-$(COMPOSE_PERSISTENT) down --remove-orphans

compose-reset:
	-$(COMPOSE) down --remove-orphans -v
	-$(COMPOSE_PERSISTENT) down --remove-orphans -v
	$(MAKE) compose-up

# Native engine profile (T-145; ADR-0008/0009). labldapd self-applies the
# engine plan and serves the lab CA certificate directly, so there is no
# setuptls publish/import (dsctl) step. LABLDAP_TLS_CA is the lab CA itself.
# Runtime bring-up requires T-143 (labldapd serve), T-144 (native bootstrap
# reconcilers), and T-146 (control engine wiring); the targets are
# correct-by-construction against the documented labldapd CLI until then.
compose-up-native: image-native image image-bootstrap compose-preflight compose-secrets setup-tls
	# Recreate native-secret-prep so rotated DM/TLS files reach directory-secrets.
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) up -d --no-deps --force-recreate native-secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) wait native-secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) up -d --wait --remove-orphans directory
	# Recreate secret-prep so setupsecrets --force copies into control-secrets.
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) up -d --no-deps --force-recreate secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) wait secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE) up -d --wait --remove-orphans --force-recreate control

compose-up-native-persistent: image-native image image-bootstrap compose-preflight compose-secrets setup-tls
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) up -d --no-deps --force-recreate native-secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) wait native-secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) up -d --wait --remove-orphans directory
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) up -d --no-deps --force-recreate secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) wait secret-prep
	LABLDAP_SCENARIO_FILE=$(COMPOSE_NATIVE_PERSISTENT_SCENARIO) LABLDAP_TLS_CA=$(COMPOSE_TLS)/ca.crt \
		$(COMPOSE_NATIVE_PERSISTENT) up -d --wait --remove-orphans --force-recreate control

compose-down-native:
	-$(COMPOSE_NATIVE_EPHEMERAL) down --remove-orphans
	-$(COMPOSE_NATIVE_PERSISTENT) down --remove-orphans

compose-reset-native:
	-$(COMPOSE_NATIVE_EPHEMERAL) down --remove-orphans -v
	-$(COMPOSE_NATIVE_PERSISTENT) down --remove-orphans -v
	$(MAKE) compose-up-native

image-native:
	docker build \
		-f deploy/docker/Dockerfile.labldapd \
		--build-arg GO_IMAGE=$(GO_IMAGE) \
		--build-arg ALPINE_IMAGE=$(LABLDAPD_BASE) \
		$(IMAGE_BUILD_ARGS) \
		-t labldapd:dev \
		.
	@docker run --rm labldapd:dev version >/dev/null
	@docker run --rm labldapd:dev >/dev/null
	@printf '%s\n' 'image-native: labldapd:dev version=$(VERSION)'
	@printf '%s\n' 'image-native: serve smoke (health listener) lands with T-143; run make compose-up-native once T-143/T-144/T-146 merge'

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

LABLDAP_PLATFORMS ?= linux/amd64

image-multiarch: archcheck
	@printf '%s\n' "image-multiarch: platforms=$(LABLDAP_PLATFORMS) (advertised list only; see deploy/docker/architectures.md)"
	docker buildx build \
		-f deploy/docker/Dockerfile.control \
		--platform $(LABLDAP_PLATFORMS) \
		--build-arg GO_IMAGE=$(GO_IMAGE) \
		--build-arg NODE_IMAGE=$(NODE_IMAGE) \
		--build-arg ALPINE_IMAGE=$(ALPINE_IMAGE) \
		$(IMAGE_BUILD_ARGS) \
		-t labldap-control:dev \
		--load \
		.
	docker buildx build \
		-f deploy/docker/Dockerfile.bootstrap \
		--platform $(LABLDAP_PLATFORMS) \
		--build-arg DIRSRV_IMAGE=$(DIRSRV_IMAGE) \
		--build-arg GO_IMAGE=$(GO_IMAGE) \
		$(IMAGE_BUILD_ARGS) \
		-t labldap-bootstrap:dev \
		--load \
		.
	@cver=$$(docker run --rm labldap-control:dev version); \
	bver=$$(docker run --rm labldap-bootstrap:dev version); \
	cfield=$$(printf '%s\n' "$$cver" | sed -n 's/.*version=//p' | awk '{print $$1}'); \
	bfield=$$(printf '%s\n' "$$bver" | sed -n 's/.*version=//p' | awk '{print $$1}'); \
	if [ "$$cfield" != "$$bfield" ]; then \
		printf '%s\n' "image-multiarch: version mismatch control=$$cfield bootstrap=$$bfield"; \
		exit 1; \
	fi
	@printf '%s\n' "image-multiarch: control and bootstrap version=$$cfield"

sbom:
	$(GO) run ./tools/sbom dist/sbom/source.cdx.json

scan:
	$(GO) run ./tools/imagescan

checksums:
	$(GO) run ./tools/releasecheck dist/release

archcheck:
	$(GO) run ./tools/archcheck

dataset:
	$(GO) run ./tools/dataset --users 50 --groups 5 --out dist/dataset/small.yaml

verify: format lint generate generate-drift test-unit test-security sbom checksums archcheck
	@printf '%s\n' 'verify: ok'
