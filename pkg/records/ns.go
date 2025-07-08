package records

import (
	"bytes"
	"fmt"

	"dklbreitling/goDNS/pkg/dns"
)

// NSRecord represents an NS (name server) record
type NSRecord struct {
	NameServer []dns.Label
}

// NewNSRecord creates a new NS record from domain labels
func NewNSRecord(nameserver []dns.Label) *NSRecord {
	return &NSRecord{NameServer: nameserver}
}

// NewNSRecordFromString creates a new NS record from a string
func NewNSRecordFromString(nameserver string) *NSRecord {
	return &NSRecord{NameServer: dns.StringToLabels(nameserver)}
}

// Bytes returns the wire format representation of the NS record
func (ns *NSRecord) Bytes() []byte {
	buf := new(bytes.Buffer)
	for _, label := range ns.NameServer {
		buf.Write(label.ToBytes())
	}
	return buf.Bytes()
}

// String returns the string representation of the NS record
func (ns *NSRecord) String() string {
	return fmt.Sprintf("NAME: %s", dns.LabelsToString(ns.NameServer))
}

// Type returns the DNS record type
func (ns *NSRecord) Type() dns.QType {
	return dns.TypeNS
}
