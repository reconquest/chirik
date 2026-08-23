GO ?= go

.PHONY: all chirik chiriked test lint clean

all: chirik chiriked

chirik:
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/chirik

chiriked:
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/chiriked

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

clean:
	rm -f chirik chiriked
