PLUGIN_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

.PHONY: all
all: test converter

.PHONY: converter
converter:
	go build -ldflags "-X github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter.version=$(VERSION)" -o ./bin/nvrules2re ./cmd/nvrules2re

.PHONY: converter-cross
converter-cross:
	@mkdir -p bin/
	@for platform in $(PLUGIN_PLATFORMS); do \
		os=$$(echo $$platform | cut -d/ -f1); \
		arch=$$(echo $$platform | cut -d/ -f2); \
		out=bin/nvrules2re/nvrules2re-$$os-$$arch; \
		echo "Building $$out ..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build \
			-ldflags "-X github.com/neuvector/neuvector-runtime-enforcer-policy-converter/internal/converter.version=$(VERSION)" \
			-o $$out \
			./cmd/nvrules2re; \
	done
	@echo "Cross-build complete. Artifacts in bin/nvrules2re/"

.PHONY: test
test: ## Run tests.
	go test ./... -race -test.v -coverprofile coverage/cover.out -covermode=atomic

.PHONY: test-e2e
test-e2e: converter ## Run e2e tests (creates a KinD cluster automatically).
	go test -tags e2e ./test/e2e/... -v -count=1 -timeout 10m
