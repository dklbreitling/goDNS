package records

import (
	"fmt"

	"dklbreitling/goDNS/pkg/dns"
)

// GenericRecord represents a generic DNS record for unknown or unsupported types
type GenericRecord struct {
	RecordType dns.QType
	Data       []byte
}

// NewGenericRecord creates a new generic record
func NewGenericRecord(recordType dns.QType, data []byte) *GenericRecord {
	return &GenericRecord{
		RecordType: recordType,
		Data:       make([]byte, len(data)), // Copy the data
	}
}

// Bytes returns the wire format representation of the generic record
func (g *GenericRecord) Bytes() []byte {
	result := make([]byte, len(g.Data))
	copy(result, g.Data)
	return result
}

// String returns the string representation of the generic record
func (g *GenericRecord) String() string {
	return fmt.Sprintf("RDLength: %d\tRData: % 02X", len(g.Data), g.Data)
}

// Type returns the DNS record type
func (g *GenericRecord) Type() dns.QType {
	return g.RecordType
}
