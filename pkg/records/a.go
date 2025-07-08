// Package records provides implementations of various DNS record types
package records

import (
	"fmt"
	"net"

	"dklbreitling/goDNS/pkg/dns"
)

// ARecord represents an A (IPv4 address) record
type ARecord struct {
	Address net.IP
}

// NewARecord creates a new A record from an IPv4 address
func NewARecord(ip net.IP) (*ARecord, error) {
	if ip4 := ip.To4(); ip4 != nil {
		return &ARecord{Address: ip4}, nil
	}
	return nil, fmt.Errorf("invalid IPv4 address: %v", ip)
}

// NewARecordFromString creates a new A record from a string representation
func NewARecordFromString(addr string) (*ARecord, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}
	return NewARecord(ip)
}

// Bytes returns the wire format representation of the A record
func (a *ARecord) Bytes() []byte {
	return a.Address.To4()
}

// String returns the string representation of the A record
func (a *ARecord) String() string {
	return fmt.Sprintf("ADDRESS: %s", a.Address.String())
}

// Type returns the DNS record type
func (a *ARecord) Type() dns.QType {
	return dns.TypeA
}
