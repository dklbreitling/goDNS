// Main package for the goDNS application
package main

import (
	"fmt"
	"log/slog"
	"os"

	"dklbreitling/goDNS/internal/config"
	"dklbreitling/goDNS/pkg/client"
	"dklbreitling/goDNS/pkg/dns"
)

// main is the entry point for the goDNS application
func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.DefaultConfig()

	if len(os.Args) < 2 {
		logger.Error("Usage: goDNS <domain>")
		os.Exit(1)
	}

	domain := os.Args[1]
	
	// Create DNS client
	dnsClient, err := client.New(cfg, logger)
	if err != nil {
		logger.Error("Failed to create DNS client", "error", err)
		os.Exit(1)
	}

	// Query for A records
	result, err := dnsClient.Query(domain, dns.TypeA)
	if err != nil {
		logger.Error("DNS query failed", "error", err)
		os.Exit(1)
	}

	fmt.Println("DNS Query Result:\n", result.String())
}
