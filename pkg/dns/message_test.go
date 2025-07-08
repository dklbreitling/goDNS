package dns

import (
	"testing"
)

func TestHeaderString(t *testing.T) {
	header := Header{
		ID:      0xBEEF,
		Flags:   HeaderRD,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
	
	result := header.String()
	expected := "\tID: BEEF\tFlags: 0100\tQDCount: 1\tANCount: 0\tNSCount: 0\tARCount: 0"
	
	if result != expected {
		t.Errorf("Header.String() = %q, want %q", result, expected)
	}
}

func TestHeaderToBytes(t *testing.T) {
	header := Header{
		ID:      0x1234,
		Flags:   HeaderRD,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
	
	result, err := header.toBytes()
	if err != nil {
		t.Fatalf("Header.toBytes() returned error: %v", err)
	}
	
	if len(result) != 12 {
		t.Errorf("Header.toBytes() length = %d, want 12", len(result))
	}
	
	// Check ID field (first 2 bytes)
	if result[0] != 0x12 || result[1] != 0x34 {
		t.Errorf("Header ID bytes = [%02x %02x], want [12 34]", result[0], result[1])
	}
}

func TestQuestionString(t *testing.T) {
	question := Question{
		Name:  StringToLabels("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	}
	
	result := question.String()
	expected := "\texample.com\tA\tIN"
	
	if result != expected {
		t.Errorf("Question.String() = %q, want %q", result, expected)
	}
}

func TestQuestionToBytes(t *testing.T) {
	question := Question{
		Name:  StringToLabels("example.com"),
		Type:  TypeA,
		Class: ClassIN,
	}
	
	result, err := question.toBytes()
	if err != nil {
		t.Fatalf("Question.toBytes() returned error: %v", err)
	}
	
	// Should include: 7"example"3"com"0 + 2 bytes type + 2 bytes class = 17 bytes
	expectedLength := 7 + 1 + 3 + 1 + 1 + 2 + 2 // label lengths + data + null + type + class
	if len(result) != expectedLength {
		t.Errorf("Question.toBytes() length = %d, want %d", len(result), expectedLength)
	}
}

func TestMessageString(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:      0x1234,
			Flags:   HeaderRD,
			QDCount: 1,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		Question: []Question{
			{
				Name:  StringToLabels("example.com"),
				Type:  TypeA,
				Class: ClassIN,
			},
		},
	}
	
	result := msg.String()
	
	// Check if it contains expected elements
	if !containsSubstring(result, "DNS Message") {
		t.Error("Message string should contain 'DNS Message'")
	}
	if !containsSubstring(result, "example.com") {
		t.Error("Message string should contain domain name")
	}
	if !containsSubstring(result, "A") {
		t.Error("Message string should contain record type")
	}
	if !containsSubstring(result, "IN") {
		t.Error("Message string should contain class")
	}
}

func TestMessageToBytes(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:      0x1234,
			Flags:   HeaderRD,
			QDCount: 1,
			ANCount: 0,
			NSCount: 0,
			ARCount: 0,
		},
		Question: []Question{
			{
				Name:  StringToLabels("example.com"),
				Type:  TypeA,
				Class: ClassIN,
			},
		},
	}
	
	result, err := msg.ToBytes()
	if err != nil {
		t.Fatalf("Message.ToBytes() returned error: %v", err)
	}
	
	// Should include header (12 bytes) + question
	if len(result) < 12 {
		t.Errorf("Message.ToBytes() length = %d, should be at least 12 bytes", len(result))
	}
}

// Helper function to check if a string contains a substring
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (findSubstring(s, substr) != -1)
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
