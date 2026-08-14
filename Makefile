# LabLDAP task runner. Tool versions are pinned; do not use @latest.

GO               ?= go
PNPM             ?= pnpm
export GOTOOLCHAIN ?= go1.26.5
export GOPROXY    ?= https://proxy.golang.org,direct

GOVULNCHECK_MOD  := golang.org/x/vuln/cmd/govulncheck@v1.1.4
OAPI_CODEGEN_MOD := github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.0
OPENAPI_TS_PKG   := openapi-typescript@7.13.0

.PHONY: help format lint generate generate-drift test test-unit \
	test-integration test-e2e test-security compose-up compose-down \
	compose-reset image verify frontend-install frontend-build

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
		'  compose-up         pending T-042' \
		'  compose-down       pending T-042' \
		'  compose-reset      pending T-110 (operator full engine reset)' \
		'  image              pending T-041/T-108' \
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
	$(GO) test -tags=integration ./test/integration/... -count=1 -timeout 15m

test-e2e: frontend-build
	cd test/e2e && $(PNPM) install --frozen-lockfile
	cd test/e2e && $(PNPM) exec playwright install chromium
	cd test/e2e && $(PNPM) test
	@printf '%s\n' 'test-e2e: default target is the contract mock. Set LABLDAP_E2E_BASE_URL for a live Compose/389 DS stack (T-042 residual).'

test-security:
	$(GO) run ./tools/secretscan .
	$(GO) run $(GOVULNCHECK_MOD) ./...
	$(GO) run ./tools/licensecheck

compose-up:
	@printf '%s\n' 'compose-up: pending T-042'
	@printf '%s\n' 'PENDING:compose-up'

compose-down:
	@printf '%s\n' 'compose-down: pending T-042'
	@printf '%s\n' 'PENDING:compose-down'

compose-reset:
	@printf '%s\n' 'compose-reset: pending T-110 — operator full engine reset (not REST/MCP)'
	@printf '%s\n' 'PENDING:compose-reset'

image:
	@printf '%s\n' 'image: pending T-041/T-108 — bootstrap/control images not in this milestone'
	@printf '%s\n' 'PENDING:image'

frontend-install:
	cd frontend && $(PNPM) install --frozen-lockfile

frontend-build: frontend-install
	cd frontend && $(PNPM) build

verify: format lint generate generate-drift test-unit test-security
	@printf '%s\n' 'verify: ok'
