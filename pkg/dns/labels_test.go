package dns

import (
	"reflect"
	"testing"
)

func TestStringToLabels(t *testing.T) {
	tests := []struct {
		domain   string
		expected []Label
	}{
		{
			"example.com",
			[]Label{
				{Length: 7, Data: []byte("example")},
				{Length: 3, Data: []byte("com")},
				{Length: 0, Data: nil},
			},
		},
		{
			"www.google.com",
			[]Label{
				{Length: 3, Data: []byte("www")},
				{Length: 6, Data: []byte("google")},
				{Length: 3, Data: []byte("com")},
				{Length: 0, Data: nil},
			},
		},
		{
			"",
			[]Label{{Length: 0, Data: nil}},
		},
		{
			"single",
			[]Label{
				{Length: 6, Data: []byte("single")},
				{Length: 0, Data: nil},
			},
		},
	}

	for _, test := range tests {
		result := StringToLabels(test.domain)
		if !reflect.DeepEqual(result, test.expected) {
			t.Errorf("StringToLabels(%q) = %v, want %v", test.domain, result, test.expected)
		}
	}
}

func TestLabelsToString(t *testing.T) {
	tests := []struct {
		labels   []Label
		expected string
	}{
		{
			[]Label{
				{Length: 7, Data: []byte("example")},
				{Length: 3, Data: []byte("com")},
				{Length: 0, Data: nil},
			},
			"example.com",
		},
		{
			[]Label{
				{Length: 3, Data: []byte("www")},
				{Length: 6, Data: []byte("google")},
				{Length: 3, Data: []byte("com")},
				{Length: 0, Data: nil},
			},
			"www.google.com",
		},
		{
			[]Label{{Length: 0, Data: nil}},
			"",
		},
		{
			[]Label{},
			"",
		},
	}

	for _, test := range tests {
		result := LabelsToString(test.labels)
		if result != test.expected {
			t.Errorf("LabelsToString(%v) = %q, want %q", test.labels, result, test.expected)
		}
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		domain      string
		expectError bool
	}{
		{"example.com", false},
		{"www.google.com", false},
		{"sub.domain.example.org", false},
		{"localhost", false},
		{"example.com.", false}, // trailing dot is valid
		{"", true},              // empty domain
		{"example..com", true},  // empty label
		{"very-long-subdomain-name.example.com", false},
		{"123.456.789.012", false}, // numeric domains are valid
		{"example-.com", true},     // can't end with hyphen
		{"-example.com", true},     // can't start with hyphen
		{"test_underscore.com", true}, // underscores not allowed
	}

	for _, test := range tests {
		err := ValidateDomain(test.domain)
		hasError := err != nil
		if hasError != test.expectError {
			t.Errorf("ValidateDomain(%q) error = %v, expectError = %v", test.domain, hasError, test.expectError)
		}
	}
}

func TestLabelToBytes(t *testing.T) {
	label := Label{Length: 3, Data: []byte("www")}
	expected := []byte{3, 'w', 'w', 'w'}
	result := label.ToBytes()
	
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("Label.ToBytes() = %v, want %v", result, expected)
	}
}

func TestDomainError(t *testing.T) {
	err := &DomainError{Domain: "example..com", Reason: "empty label not allowed"}
	expected := "invalid domain 'example..com': empty label not allowed"
	
	if err.Error() != expected {
		t.Errorf("DomainError.Error() = %q, want %q", err.Error(), expected)
	}
}
