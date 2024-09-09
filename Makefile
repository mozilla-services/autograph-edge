GO := GO111MODULE=on go

all: lint vet test install

version.json:
	$(GO) generate

install: version.json
	$(GO) install .
test: version.json
	MOCK_AUTOGRAPH_CALLS=1 $(GO) test -v -count=1 -covermode=count -coverprofile=coverage.out .
showcoverage: test
	$(GO) tool cover -html=coverage.out
lint:
	golint *.go
vet:
	$(GO) vet *.go

.PHONY: all install test showcoverage lint vet
