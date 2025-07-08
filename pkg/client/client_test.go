package client

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"dklbreitling/goDNS/internal/config"
	"dklbreitling/goDNS/pkg/dns"
)

func TestNewClient(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	
	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	
	if client == nil {
		t.Fatal("New() returned nil client")
	}
}

func TestNewClientInvalidConfig(t *testing.T) {
	cfg := &config.Config{
		NameServer: "", // Invalid empty server
		Protocol:   "udp",
		Timeout:    5 * time.Second,
		LogLevel:   "info",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	
	_, err := New(cfg, logger)
	if err == nil {
		t.Error("New() should return error for invalid config")
	}
}

func TestClientQueryValidation(t *testing.T) {
	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	
	client, err := New(cfg, logger)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	
	// Test invalid domain
	_, err = client.Query("", dns.TypeA)
	if err == nil {
		t.Error("Query() should return error for empty domain")
	}
	
	// Test invalid domain format
	_, err = client.Query("invalid..domain", dns.TypeA)
	if err == nil {
		t.Error("Query() should return error for invalid domain format")
	}
}

// Note: We don't test actual network queries in unit tests
// Those would be integration tests that require network access
