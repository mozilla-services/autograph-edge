all: lint vet test install

install:
	vgo install go.mozilla.org/autograph-edge
test:
	vgo test -v -covermode=count -coverprofile=coverage.out go.mozilla.org/autograph-edge
showcoverage: test
	vgo tool cover -html=coverage.out
lint:
	golint *.go
vet:
	go vet *.go
vendor:
	vgo build
