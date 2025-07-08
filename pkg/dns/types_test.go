package dns

import (
	"testing"
)

func TestQTypeString(t *testing.T) {
	tests := []struct {
		typ      QType
		expected string
	}{
		{TypeA, "A"},
		{TypeNS, "NS"},
		{TypeCNAME, "CNAME"},
		{TypeSOA, "SOA"},
		{TypePTR, "PTR"},
		{TypeMX, "MX"},
		{TypeTXT, "TXT"},
		{TypeAAAA, "AAAA"},
		{QType(999), "UNKNOWN"}, // Test unknown type
	}

	for _, test := range tests {
		if got := test.typ.String(); got != test.expected {
			t.Errorf("QType.String() = %v, want %v", got, test.expected)
		}
	}
}

func TestQClassString(t *testing.T) {
	tests := []struct {
		class    QClass
		expected string
	}{
		{ClassIN, "IN"},
		{ClassCS, "CS"},
		{ClassCH, "CH"},
		{ClassHS, "HS"},
		{ClassASTERISK, "*"},
		{QClass(999), "UNKNOWN"}, // Test unknown class
	}

	for _, test := range tests {
		if got := test.class.String(); got != test.expected {
			t.Errorf("QClass.String() = %v, want %v", got, test.expected)
		}
	}
}

func TestQTypeConstants(t *testing.T) {
	// Test that constants are properly defined
	if TypeA != 1 {
		t.Errorf("TypeA = %d, want 1", TypeA)
	}
	if TypeNS != 2 {
		t.Errorf("TypeNS = %d, want 2", TypeNS)
	}
	if TypeAAAA != 28 {
		t.Errorf("TypeAAAA = %d, want 28", TypeAAAA)
	}
}

func TestQClassConstants(t *testing.T) {
	// Test that constants are properly defined
	if ClassIN != 1 {
		t.Errorf("ClassIN = %d, want 1", ClassIN)
	}
	if ClassCS != 2 {
		t.Errorf("ClassCS = %d, want 2", ClassCS)
	}
}

func TestHeaderBitfields(t *testing.T) {
	// Test some key header bitfield constants
	if HeaderQRQuery != 0 {
		t.Errorf("HeaderQRQuery = %d, want 0", HeaderQRQuery)
	}
	if HeaderQRResponse != (1 << 15) {
		t.Errorf("HeaderQRResponse = %d, want %d", HeaderQRResponse, 1<<15)
	}
	if HeaderRD != (1 << 8) {
		t.Errorf("HeaderRD = %d, want %d", HeaderRD, 1<<8)
	}
}
