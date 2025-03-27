.PHONY: docker-build lint build

GOLANGCI_LINT_VERSION ?= v1.64

docker-build:
	@docker build -t nodekey-tools .

lint:
	@docker run --rm \
		-v "$$(pwd)":/app:ro \
		-w /app \
		golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) \
		golangci-lint run --color=always -v

build:
	@go build -o bin/nodekey-tools .
