GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: all chirik test test-audio lint clean

all: chirik

chirik:
	CGO_ENABLED=0 $(GO) build -o $@ ./cmd/chirik

test:
	$(GO) test ./...

test-audio:
	CHIRIK_AUDIO_TEST_DIR="$(CURDIR)/_tmp/audio-quality" $(GO) test -count=1 -v ./cmd/chirik -run '^TestAudioQuality$$'

lint:
	$(GO) vet ./...
	$(GO) tool karmalint ./...
	$(GOLANGCI_LINT) run ./...
	$(GOLANGCI_LINT) fmt --diff

clean:
	rm -f chirik chiriked
