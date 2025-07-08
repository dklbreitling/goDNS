.PHONY: test build clean run fmt vet lint help

# Default target
help:
	@echo "Available targets:"
	@echo "  build    - Build the goDNS binary"
	@echo "  test     - Run all tests"
	@echo "  run      - Run the program with google.com as test domain"
	@echo "  fmt      - Format Go code"
	@echo "  vet      - Run go vet"
	@echo "  lint     - Run golint (requires golint to be installed)"
	@echo "  clean    - Remove build artifacts and debug files"
	@echo "  coverage - Run tests with coverage report"

# Build the binary
build:
	go build -o goDNS ./cmd/goDNS

# Run all tests
test:
	go test -v ./...

# Run tests with coverage
coverage:
	go test -v -cover ./...
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run the program with a test domain
run: build
	./goDNS google.com

# Format Go code
fmt:
	go fmt ./...

# Run go vet
vet:
	go vet ./...

# Run golint (install with: go install golang.org/x/lint/golint@latest)
lint:
	golint ./...

# Clean build artifacts and debug files
clean:
	rm -f goDNS
	rm -f dump dumpraw dumpresponse dumpresponseraw
	rm -f coverage.out coverage.html

# Install dependencies for development
install-dev-deps:
	go install golang.org/x/lint/golint@latest
	go install golang.org/x/tools/cmd/goimports@latest

# Check if code is properly formatted
check-fmt:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "The following files need formatting:"; \
		gofmt -l .; \
		exit 1; \
	fi

# Run all checks (format, vet, test)
check: check-fmt vet test

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build -o goDNS-linux-amd64 ./cmd/goDNS
	GOOS=darwin GOARCH=amd64 go build -o goDNS-darwin-amd64 ./cmd/goDNS
	GOOS=windows GOARCH=amd64 go build -o goDNS-windows-amd64.exe ./cmd/goDNS
