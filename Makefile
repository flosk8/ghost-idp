.PHONY: test build run clean docker-build docker-run help

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run all tests
	go test -v -race -count=1 ./...

test-coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short: ## Run tests without long-running tests
	go test -v -short ./...

build: ## Build the binary
	go build -v -o ghost-idp .

build-version: ## Build with version information
	go build -ldflags="-X main.Version=$$(git describe --tags --always --dirty)" -o ghost-idp .

run: ## Run the application
	go run .

clean: ## Clean build artifacts
	rm -f ghost-idp
	rm -f coverage.out coverage.html

docker-build: ## Build Docker image
	docker build -t ghost-idp:local .

docker-run: ## Run Docker container locally
	docker run -p 8080:8080 \
		-v $$(pwd)/tls.key:/app/tls.key \
		-v $$(pwd)/config.yaml:/app/config.yaml \
		-e JWT_KEY_PATH=/app/tls.key \
		--name ghost-idp-test \
		--rm \
		ghost-idp:local

vet: ## Run go vet
	go vet ./...

fmt: ## Format code
	go fmt ./...

lint: ## Run golangci-lint (if installed)
	@which golangci-lint > /dev/null || (echo "golangci-lint not installed. Install from https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run

deps: ## Download dependencies
	go mod download
	go mod tidy

update-deps: ## Update dependencies
	go get -u ./...
	go mod tidy

generate-key: ## Generate a new ECDSA key for testing
	openssl ecparam -name prime256v1 -genkey -noout -out tls.key
	@echo "Generated new ECDSA key: tls.key"

dev: ## Run in development mode with auto-reload (requires air)
	@which air > /dev/null || (echo "air not installed. Run: go install github.com/cosmtrek/air@latest" && exit 1)
	air

.DEFAULT_GOAL := help

