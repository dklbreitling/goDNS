package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Message represents a complete DNS message according to RFC 1035
type Message struct {
	Header     Header
	Question   []Question
	Answer     []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

// Header represents the DNS message header according to RFC 1035 Section 4.1.1
type Header struct {
	ID      uint16         // Query identifier
	Flags   HeaderBitfield // Flags and codes
	QDCount uint16         // Number of questions
	ANCount uint16         // Number of answer RRs
	NSCount uint16         // Number of authority RRs
	ARCount uint16         // Number of additional RRs
}

// Question represents a DNS question according to RFC 1035 Section 4.1.2
type Question struct {
	Name  []Label // Domain name as sequence of labels
	Type  QType   // Query type
	Class QClass  // Query class
}

// Label represents a DNS label according to RFC 1035
type Label struct {
	Length byte
	Data   []byte
}

// ResourceRecord represents a DNS resource record according to RFC 1035 Section 4.1.3
type ResourceRecord struct {
	Name     []Label      // Domain name
	Type     QType        // RR type
	Class    QClass       // RR class
	TTL      int32        // Time to live
	RDLength uint16       // Resource data length
	RData    ResourceData // Resource data
}

// ResourceData interface for different types of DNS record data
type ResourceData interface {
	Bytes() []byte
	String() string
	Type() QType
}

// ToBytes converts the DNS message to wire format
func (m *Message) ToBytes() ([]byte, error) {
	buf := new(bytes.Buffer)

	// Write header
	headerBytes, err := m.Header.toBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}
	buf.Write(headerBytes)

	// Write questions
	for _, q := range m.Question {
		qBytes, err := q.toBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize question: %w", err)
		}
		buf.Write(qBytes)
	}

	// Write answer RRs
	for _, rr := range m.Answer {
		rrBytes, err := rr.toBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize answer RR: %w", err)
		}
		buf.Write(rrBytes)
	}

	// Write authority RRs
	for _, rr := range m.Authority {
		rrBytes, err := rr.toBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize authority RR: %w", err)
		}
		buf.Write(rrBytes)
	}

	// Write additional RRs
	for _, rr := range m.Additional {
		rrBytes, err := rr.toBytes()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize additional RR: %w", err)
		}
		buf.Write(rrBytes)
	}

	return buf.Bytes(), nil
}

// String returns a human-readable representation of the DNS message
func (m *Message) String() string {
	var buf bytes.Buffer
	
	buf.WriteString("; DNS Message\n")
	buf.WriteString("; Header:\n")
	buf.WriteString(m.Header.String())
	
	if m.Header.QDCount > 0 {
		buf.WriteString("\n; Question:\n")
		for _, q := range m.Question {
			buf.WriteString(q.String())
			buf.WriteString("\n")
		}
	}
	
	if m.Header.ANCount > 0 {
		buf.WriteString("\n; Answer:\n")
		for _, rr := range m.Answer {
			buf.WriteString(rr.String())
			buf.WriteString("\n")
		}
	}
	
	if m.Header.NSCount > 0 {
		buf.WriteString("\n; Authority:\n")
		for _, rr := range m.Authority {
			buf.WriteString(rr.String())
			buf.WriteString("\n")
		}
	}
	
	if m.Header.ARCount > 0 {
		buf.WriteString("\n; Additional:\n")
		for _, rr := range m.Additional {
			buf.WriteString(rr.String())
			buf.WriteString("\n")
		}
	}
	
	return buf.String()
}

// toBytes converts the header to wire format
func (h *Header) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	fields := []interface{}{h.ID, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount}
	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return nil, fmt.Errorf("failed to write header field: %w", err)
		}
	}
	
	return buf.Bytes(), nil
}

// String returns a human-readable representation of the header
func (h *Header) String() string {
	return fmt.Sprintf("\tID: %04X\tFlags: %04X\tQDCount: %d\tANCount: %d\tNSCount: %d\tARCount: %d",
		h.ID, h.Flags, h.QDCount, h.ANCount, h.NSCount, h.ARCount)
}

// toBytes converts the question to wire format
func (q *Question) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write labels
	for _, label := range q.Name {
		buf.Write(label.ToBytes())
	}
	
	// Write type and class
	if err := binary.Write(buf, binary.BigEndian, q.Type); err != nil {
		return nil, fmt.Errorf("failed to write question type: %w", err)
	}
	if err := binary.Write(buf, binary.BigEndian, q.Class); err != nil {
		return nil, fmt.Errorf("failed to write question class: %w", err)
	}
	
	return buf.Bytes(), nil
}

// String returns a human-readable representation of the question
func (q *Question) String() string {
	domain := LabelsToString(q.Name)
	return fmt.Sprintf("\t%s\t%s\t%s", domain, q.Type.String(), q.Class.String())
}

// ToBytes converts the label to wire format
func (l *Label) ToBytes() []byte {
	return append([]byte{l.Length}, l.Data...)
}

// toBytes converts the resource record to wire format
func (rr *ResourceRecord) toBytes() ([]byte, error) {
	buf := new(bytes.Buffer)
	
	// Write name labels
	for _, label := range rr.Name {
		buf.Write(label.ToBytes())
	}
	
	// Write type, class, TTL, and RDLength
	fields := []interface{}{rr.Type, rr.Class, rr.TTL, rr.RDLength}
	for _, field := range fields {
		if err := binary.Write(buf, binary.BigEndian, field); err != nil {
			return nil, fmt.Errorf("failed to write RR field: %w", err)
		}
	}
	
	// Write resource data
	buf.Write(rr.RData.Bytes())
	
	return buf.Bytes(), nil
}

// String returns a human-readable representation of the resource record
func (rr *ResourceRecord) String() string {
	domain := LabelsToString(rr.Name)
	return fmt.Sprintf("\t%s\t%s\t%s\tTTL: %d\t%s",
		domain, rr.Type.String(), rr.Class.String(), rr.TTL, rr.RData.String())
}
