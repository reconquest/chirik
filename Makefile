GO ?= go

.PHONY: all chirik test lint clean

all: chirik

chirik:
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/chirik

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

clean:
	rm -f chirik chiriked
