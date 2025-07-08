# goDNS - A DNS Client Implementation in Go

A DNS client implementation written in Go that follows RFC 1035 specifications. This project demonstrates low-level DNS protocol handling with a clean, extensible architecture.

## Features

- ✅ RFC 1035 compliant DNS implementation
- ✅ Support for A, AAAA, and NS record types  
- ✅ Both UDP and TCP protocols
- ✅ DNS name compression handling
- ✅ Proper error handling and validation
- ✅ Extensible record type system
- ✅ Clean package architecture
- ✅ Comprehensive testing
- ✅ Domain name validation

## Project Structure

```
goDNS/
├── cmd/goDNS/           # Main application entry point
├── pkg/
│   ├── dns/             # Core DNS types and message handling
│   ├── client/          # DNS client implementation
│   └── records/         # DNS record type implementations
├── internal/
│   └── config/          # Configuration management
├── tests/               # Test files
├── Makefile            # Build automation
└── README.md           # This file
```

### Package Overview

- **`pkg/dns`**: Core DNS protocol types, constants, and message structures
- **`pkg/client`**: DNS client with query/response handling
- **`pkg/records`**: Extensible record type implementations (A, AAAA, NS, Generic)
- **`internal/config`**: Configuration management and validation
- **`cmd/goDNS`**: Command-line application entry point

## Quick Start

### Prerequisites

- Go 1.22.1 or later
- Make (optional, for build automation)

### Installation

```bash
# Clone the repository
git clone https://github.com/dklbreitling/goDNS.git
cd goDNS

# Build the binary
make build
# OR
go build -o goDNS ./cmd/goDNS
```

### Usage

```bash
# Query a domain for A records
./goDNS google.com

# Query with different record types (coming soon)
./goDNS -type AAAA google.com
```

## Development

### Building

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Format code
make fmt

# Run tests
make test

# Run tests with coverage
make coverage

# Run all checks (format, vet, test)
make check
```

### Testing

The project includes comprehensive tests for all components:

```bash
# Run all tests
make test

# Run tests with verbose output
go test -v ./...

# Generate coverage report
make coverage
```

### Adding New Record Types

The architecture makes it easy to add new DNS record types:

1. Create a new file in `pkg/records/`
2. Implement the `dns.ResourceData` interface:
   ```go
   type ResourceData interface {
       Bytes() []byte
       String() string
       Type() dns.QType
   }
   ```
3. Add parsing logic in `pkg/client/client.go`
4. Add the new record type to `pkg/dns/types.go`

### Example: Adding MX Record Support

```go
// pkg/records/mx.go
package records

import (
    "dklbreitling/goDNS/pkg/dns"
)

type MXRecord struct {
    Priority uint16
    Exchange []dns.Label
}

func (mx *MXRecord) Bytes() []byte { /* implementation */ }
func (mx *MXRecord) String() string { /* implementation */ }
func (mx *MXRecord) Type() dns.QType { return dns.TypeMX }
```

## Configuration

The DNS client supports various configuration options:

```go
cfg := &config.Config{
    NameServer:       "8.8.8.8:53",      // DNS server
    Protocol:         "udp",              // "udp" or "tcp"
    Timeout:          5 * time.Second,    // Query timeout
    RecursionDesired: true,               // Set RD bit
    RetryCount:       3,                  // Retry attempts
    Debug:            false,              // Debug output
    LogLevel:         "info",             // Log level
}
```

## Architecture Principles

### Clean Architecture
- **Separation of Concerns**: Each package has a single responsibility
- **Dependency Inversion**: Interfaces define contracts between layers
- **Testability**: All components are easily testable in isolation

### Extensibility
- **Interface-Based**: New record types implement common interfaces
- **Pluggable Components**: Easy to swap implementations
- **Configuration-Driven**: Behavior controlled through configuration

### Error Handling
- **Explicit Errors**: All functions return explicit error values
- **Contextual Information**: Errors include relevant context
- **Graceful Degradation**: Unknown record types fall back to generic handling

## DNS Protocol Compliance

This implementation follows RFC 1035 specifications:

- **Message Format**: Proper header, question, and resource record formatting
- **Name Compression**: Full support for DNS name compression
- **Wire Format**: Correct binary encoding/decoding
- **Record Types**: Standard record types with room for extension

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`make check`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Code Style

- Follow Go conventions
- Run `make fmt` before committing
- Ensure `make check` passes
- Add tests for new functionality
- Document public APIs

## Performance Considerations

- **Memory Efficient**: Minimal allocations in hot paths
- **Concurrent Safe**: Can be used from multiple goroutines
- **Resource Management**: Proper cleanup of network connections
- **Timeout Handling**: Configurable timeouts prevent hanging

## Security Considerations

- **Input Validation**: All domain names are validated
- **Buffer Overflow Protection**: Safe binary parsing
- **Network Security**: Proper connection handling
- **DNS Security**: Foundation for DNSSEC support (future)

## Roadmap

- [ ] Command-line argument parsing (flags)
- [ ] More record types (MX, TXT, CNAME, SOA)
- [ ] DNSSEC validation
- [ ] Caching support
- [ ] Concurrent queries
- [ ] DNS over HTTPS (DoH)
- [ ] Prometheus metrics
- [ ] Configuration file support

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) - Domain Names Implementation and Specification
- [RFC 3596](https://datatracker.ietf.org/doc/html/rfc3596) - DNS Extensions to Support IP Version 6
- Go standard library authors for excellent networking primitives
