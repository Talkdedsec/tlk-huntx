BINARY := huntx
PKG := ./cmd/huntx

.PHONY: build test vet fmt lint clean

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2 run --timeout 5m ./...

clean:
	rm -f $(BINARY) $(BINARY).exe huntx.graph.json huntx.findings.jsonl huntx.feedback.json
