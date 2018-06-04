all: lint vet test install

install:
	vgo install go.mozilla.org/autograph-edge
test:
	go test go.mozilla.org/autograph-edge
lint:
	golint *.go
vet:
	go vet *.go
vendor:
	vgo build
