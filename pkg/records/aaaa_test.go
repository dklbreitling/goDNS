package records

import (
	"dklbreitling/goDNS/pkg/dns"
	"net"
	"testing"
)

func TestNewAAAARecord(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	record, err := NewAAAARecord(ip)
	if err != nil {
		t.Fatalf("NewAAAARecord returned error: %v", err)
	}
	
	if record == nil {
		t.Fatal("NewAAAARecord returned nil")
	}
	
	if !record.Address.Equal(ip) {
		t.Errorf("AAAARecord.Address = %v, want %v", record.Address, ip)
	}
}

func TestNewAAAARecordInvalidIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.1") // IPv4 address
	_, err := NewAAAARecord(ip)
	if err == nil {
		t.Error("NewAAAARecord should return error for IPv4 address")
	}
}

func TestAAAARecordBytes(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	record, err := NewAAAARecord(ip)
	if err != nil {
		t.Fatalf("NewAAAARecord returned error: %v", err)
	}
	
	result := record.Bytes()
	
	if len(result) != 16 {
		t.Errorf("AAAARecord.Bytes() length = %d, want 16", len(result))
	}
	
	// Check that the IP bytes match
	expected := ip.To16()
	for i, b := range expected {
		if result[i] != b {
			t.Errorf("AAAARecord.Bytes()[%d] = %d, want %d", i, result[i], b)
		}
	}
}

func TestAAAARecordString(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	record, err := NewAAAARecord(ip)
	if err != nil {
		t.Fatalf("NewAAAARecord returned error: %v", err)
	}
	
	expected := "ADDRESS: 2001:db8::1"
	result := record.String()
	
	if result != expected {
		t.Errorf("AAAARecord.String() = %q, want %q", result, expected)
	}
}

func TestAAAARecordType(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	record, err := NewAAAARecord(ip)
	if err != nil {
		t.Fatalf("NewAAAARecord returned error: %v", err)
	}
	
	if record.Type() != dns.TypeAAAA {
		t.Errorf("AAAARecord.Type() = %v, want %v", record.Type(), dns.TypeAAAA)
	}
}
