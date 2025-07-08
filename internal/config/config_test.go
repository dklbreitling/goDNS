package config

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	if cfg.NameServer != "198.41.0.4:53" {
		t.Errorf("Default NameServer = %q, want %q", cfg.NameServer, "198.41.0.4:53")
	}
	
	if cfg.Protocol != "udp" {
		t.Errorf("Default protocol = %q, want %q", cfg.Protocol, "udp")
	}
	
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Default timeout = %v, want %v", cfg.Timeout, 5*time.Second)
	}
	
	if !cfg.RecursionDesired {
		t.Error("Default RecursionDesired should be true")
	}
	
	if cfg.RetryCount != 3 {
		t.Errorf("Default RetryCount = %d, want 3", cfg.RetryCount)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name:        "valid UDP config",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "udp", Timeout: 5 * time.Second, RetryCount: 3, LogLevel: "info"},
			expectError: false,
		},
		{
			name:        "valid TCP config",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "tcp", Timeout: 5 * time.Second, RetryCount: 3, LogLevel: "info"},
			expectError: false,
		},
		{
			name:        "invalid protocol",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "http", Timeout: 5 * time.Second, RetryCount: 3, LogLevel: "info"},
			expectError: true,
		},
		{
			name:        "invalid nameserver",
			config:      &Config{NameServer: "", Protocol: "udp", Timeout: 5 * time.Second, RetryCount: 3, LogLevel: "info"},
			expectError: true,
		},
		{
			name:        "zero timeout",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "udp", Timeout: 0, RetryCount: 3, LogLevel: "info"},
			expectError: true,
		},
		{
			name:        "negative retry count",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "udp", Timeout: 5 * time.Second, RetryCount: -1, LogLevel: "info"},
			expectError: true,
		},
		{
			name:        "invalid log level",
			config:      &Config{NameServer: "8.8.8.8:53", Protocol: "udp", Timeout: 5 * time.Second, RetryCount: 3, LogLevel: "invalid"},
			expectError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
			if test.expectError && err == nil {
				t.Error("Expected validation error, got none")
			}
			if !test.expectError && err != nil {
				t.Errorf("Unexpected validation error: %v", err)
			}
		})
	}
}

func TestGetMaxMessageSize(t *testing.T) {
	tests := []struct {
		protocol string
		expected int
	}{
		{"udp", 512},
		{"tcp", 65535},
		{"invalid", 512}, // Should return safe default
	}

	for _, test := range tests {
		cfg := &Config{Protocol: test.protocol}
		result := cfg.GetMaxMessageSize()
		
		if result != test.expected {
			t.Errorf("GetMaxMessageSize() for protocol %q = %d, want %d", test.protocol, result, test.expected)
		}
	}
}
