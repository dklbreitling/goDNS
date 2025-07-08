package records

import (
	"testing"
	
	"dklbreitling/goDNS/pkg/dns"
)

func TestNewNSRecord(t *testing.T) {
	labels := dns.StringToLabels("ns.example.com")
	record := NewNSRecord(labels)
	
	if record == nil {
		t.Fatal("NewNSRecord returned nil")
	}
	
	if len(record.NameServer) != len(labels) {
		t.Errorf("NSRecord.NameServer length = %d, want %d", len(record.NameServer), len(labels))
	}
}

func TestNewNSRecordFromString(t *testing.T) {
	domain := "ns.example.com"
	record := NewNSRecordFromString(domain)
	
	if record == nil {
		t.Fatal("NewNSRecordFromString returned nil")
	}
	
	result := dns.LabelsToString(record.NameServer)
	if result != domain {
		t.Errorf("NSRecord domain = %q, want %q", result, domain)
	}
}

func TestNSRecordString(t *testing.T) {
	domain := "ns.example.com"
	record := NewNSRecordFromString(domain)
	
	expected := "NAME: ns.example.com"
	result := record.String()
	
	if result != expected {
		t.Errorf("NSRecord.String() = %q, want %q", result, expected)
	}
}

func TestNSRecordBytes(t *testing.T) {
	domain := "ns.example.com"
	record := NewNSRecordFromString(domain)
	
	result := record.Bytes()
	
	// Should start with length of first label
	if len(result) == 0 {
		t.Error("NSRecord.Bytes() should not be empty")
	}
	
	if result[0] != 2 { // "ns" has length 2
		t.Errorf("NSRecord.Bytes()[0] = %d, want 2", result[0])
	}
}

func TestNSRecordType(t *testing.T) {
	record := NewNSRecordFromString("ns.example.com")
	
	if record.Type() != dns.TypeNS {
		t.Errorf("NSRecord.Type() = %v, want %v", record.Type(), dns.TypeNS)
	}
}
