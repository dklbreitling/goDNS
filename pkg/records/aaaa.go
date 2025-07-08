package records

import (
	"fmt"
	"net"

	"dklbreitling/goDNS/pkg/dns"
)

// AAAARecord represents an AAAA (IPv6 address) record
type AAAARecord struct {
	Address net.IP
}

// NewAAAARecord creates a new AAAA record from an IPv6 address
func NewAAAARecord(ip net.IP) (*AAAARecord, error) {
	if ip.To4() != nil {
		return nil, fmt.Errorf("IPv4 address provided for AAAA record: %v", ip)
	}
	if ip.To16() == nil {
		return nil, fmt.Errorf("invalid IPv6 address: %v", ip)
	}
	return &AAAARecord{Address: ip.To16()}, nil
}

// NewAAAARecordFromString creates a new AAAA record from a string representation
func NewAAAARecordFromString(addr string) (*AAAARecord, error) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}
	return NewAAAARecord(ip)
}

// Bytes returns the wire format representation of the AAAA record
func (aaaa *AAAARecord) Bytes() []byte {
	return aaaa.Address.To16()
}

// String returns the string representation of the AAAA record
func (aaaa *AAAARecord) String() string {
	return fmt.Sprintf("ADDRESS: %s", aaaa.Address.String())
}

// Type returns the DNS record type
func (aaaa *AAAARecord) Type() dns.QType {
	return dns.TypeAAAA
}
