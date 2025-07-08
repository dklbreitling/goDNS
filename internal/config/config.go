// Package config handles configuration for the DNS client
package config

import (
	"fmt"
	"net"
	"time"
)

// Config holds the DNS client configuration
type Config struct {
	// Network settings
	NameServer string        // DNS server address (host:port)
	Protocol   string        // "udp" or "tcp"
	Timeout    time.Duration // Query timeout

	// Query settings
	RecursionDesired bool // Set RD bit in queries
	RetryCount       int  // Number of retries on failure

	// Debug settings
	Debug     bool   // Enable debug output
	DumpFiles bool   // Enable hex dump files
	LogLevel  string // Log level (debug, info, warn, error)
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		NameServer:       "198.41.0.4:53", // Root server A
		Protocol:         "udp",
		Timeout:          5 * time.Second,
		RecursionDesired: true,
		RetryCount:       3,
		Debug:            false,
		DumpFiles:        false,
		LogLevel:         "info",
	}
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate name server
	if c.NameServer == "" {
		return fmt.Errorf("name server cannot be empty")
	}
	
	host, port, err := net.SplitHostPort(c.NameServer)
	if err != nil {
		return fmt.Errorf("invalid name server format: %w", err)
	}
	
	if net.ParseIP(host) == nil {
		// Try to resolve hostname
		if _, err := net.ResolveIPAddr("ip", host); err != nil {
			return fmt.Errorf("cannot resolve name server hostname %s: %w", host, err)
		}
	}
	
	if port == "" {
		return fmt.Errorf("name server port is required")
	}
	
	// Validate protocol
	if c.Protocol != "udp" && c.Protocol != "tcp" {
		return fmt.Errorf("protocol must be 'udp' or 'tcp', got '%s'", c.Protocol)
	}
	
	// Validate timeout
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %v", c.Timeout)
	}
	
	// Validate retry count
	if c.RetryCount < 0 {
		return fmt.Errorf("retry count cannot be negative, got %d", c.RetryCount)
	}
	
	// Validate log level
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if !validLevels[c.LogLevel] {
		return fmt.Errorf("invalid log level '%s', must be one of: debug, info, warn, error", c.LogLevel)
	}
	
	return nil
}

// GetMaxMessageSize returns the maximum message size for the configured protocol
func (c *Config) GetMaxMessageSize() int {
	switch c.Protocol {
	case "tcp":
		return 65535 // Theoretical maximum for TCP
	case "udp":
		return 512 // RFC 1035 limit for UDP
	default:
		return 512 // Safe default
	}
}
