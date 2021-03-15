GO := GO111MODULE=on go

all: lint vet test install

install:
	$(GO) install go.mozilla.org/autograph-edge
test:
	MOCK_AUTOGRAPH_CALLS=1 $(GO) test -v -count=1 -covermode=count -coverprofile=coverage.out go.mozilla.org/autograph-edge
showcoverage: test
	$(GO) tool cover -html=coverage.out
lint:
	golint *.go
vet:
	$(GO) vet *.go
