# PromptSentinel Go SDK Makefile

.PHONY: help build test test-coverage lint fmt clean example deps

# Default target
help: ## Show this help message
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

deps: ## Download and verify dependencies
	go mod download
	go mod verify
	go mod tidy

build: deps ## Build the SDK
	go build ./...

test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short: ## Run short tests
	go test -short ./...

lint: ## Run linter (requires golangci-lint)
	golangci-lint run

fmt: ## Format code
	go fmt ./...
	goimports -w .

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	go clean ./...
	rm -f coverage.out coverage.html

example: build ## Run example
	cd cmd/example && go run main.go

# Development targets
dev-setup: ## Setup development environment
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

check: fmt vet lint test ## Run all checks

# CI/CD targets
ci: deps check test-coverage ## Run CI pipeline

release-check: ## Check if ready for release
	@echo "Checking release readiness..."
	go mod verify
	golangci-lint run
	go test ./...
	@echo "✅ Ready for release"