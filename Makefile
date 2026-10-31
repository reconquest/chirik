GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: all chirik test lint clean

all: chirik

chirik:
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/chirik

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...
	$(GO) tool karmalint ./...
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) fmt --diff

clean:
	rm -f chirik chiriked
