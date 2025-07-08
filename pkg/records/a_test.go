package records

import (
	"dklbreitling/goDNS/pkg/dns"
	"net"
	"testing"
)

func TestNewARecord(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	record, err := NewARecord(ip)
	if err != nil {
		t.Fatalf("NewARecord returned error: %v", err)
	}
	
	if record == nil {
		t.Fatal("NewARecord returned nil")
	}
	
	if !record.Address.Equal(ip.To4()) {
		t.Errorf("ARecord.Address = %v, want %v", record.Address, ip.To4())
	}
}

func TestNewARecordInvalidIP(t *testing.T) {
	ip := net.ParseIP("2001:db8::1") // IPv6 address
	_, err := NewARecord(ip)
	if err == nil {
		t.Error("NewARecord should return error for IPv6 address")
	}
}

func TestNewARecordFromString(t *testing.T) {
	tests := []struct {
		addr        string
		expectError bool
	}{
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"0.0.0.0", false},
		{"255.255.255.255", false},
		{"invalid", true},
		{"2001:db8::1", true}, // IPv6
		{"", true},
	}

	for _, test := range tests {
		record, err := NewARecordFromString(test.addr)
		
		if test.expectError {
			if err == nil {
				t.Errorf("NewARecordFromString(%q) should return error", test.addr)
			}
		} else {
			if err != nil {
				t.Errorf("NewARecordFromString(%q) returned error: %v", test.addr, err)
			}
			if record == nil {
				t.Errorf("NewARecordFromString(%q) returned nil record", test.addr)
			}
		}
	}
}

func TestARecordBytes(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	record, err := NewARecord(ip)
	if err != nil {
		t.Fatalf("NewARecord returned error: %v", err)
	}
	
	expected := []byte{192, 168, 1, 1}
	result := record.Bytes()
	
	if len(result) != 4 {
		t.Errorf("ARecord.Bytes() length = %d, want 4", len(result))
	}
	
	for i, b := range expected {
		if result[i] != b {
			t.Errorf("ARecord.Bytes()[%d] = %d, want %d", i, result[i], b)
		}
	}
}

func TestARecordString(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	record, err := NewARecord(ip)
	if err != nil {
		t.Fatalf("NewARecord returned error: %v", err)
	}
	
	expected := "ADDRESS: 192.168.1.1"
	result := record.String()
	
	if result != expected {
		t.Errorf("ARecord.String() = %q, want %q", result, expected)
	}
}

func TestARecordType(t *testing.T) {
	ip := net.ParseIP("192.168.1.1")
	record, err := NewARecord(ip)
	if err != nil {
		t.Fatalf("NewARecord returned error: %v", err)
	}
	
	if record.Type() != dns.TypeA {
		t.Errorf("ARecord.Type() = %v, want %v", record.Type(), dns.TypeA)
	}
}
