GO := GO111MODULE=on go

all: lint vet test install

install:
	$(GO) install go.mozilla.org/autograph-edge
test:
	$(GO) test -v -covermode=count -coverprofile=coverage.out go.mozilla.org/autograph-edge
showcoverage: test
	$(GO) tool cover -html=coverage.out
lint:
	golint *.go
vet:
	$(GO) vet *.go
