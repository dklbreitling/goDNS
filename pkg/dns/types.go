// Package dns provides DNS protocol types and constants according to RFC 1035
package dns

// QType represents DNS query types according to RFC 1035
type QType uint16

// QClass represents DNS query classes according to RFC 1035
type QClass uint16

// DNS Query Types - See RFC 1035 Section 3.2.2 and 3.2.3
const (
	TypeA     QType = 1  // A host address
	TypeNS    QType = 2  // An authoritative name server
	TypeMD    QType = 3  // A mail destination (Obsolete - use MX)
	TypeMF    QType = 4  // A mail forwarder (Obsolete - use MX)
	TypeCNAME QType = 5  // The canonical name for an alias
	TypeSOA   QType = 6  // Marks the start of a zone of authority
	TypeMB    QType = 7  // A mailbox domain name (EXPERIMENTAL)
	TypeMG    QType = 8  // A mail group member (EXPERIMENTAL)
	TypeMR    QType = 9  // A mail rename domain name (EXPERIMENTAL)
	TypeNULL  QType = 10 // A null RR (EXPERIMENTAL)
	TypeWKS   QType = 11 // A well known service description
	TypePTR   QType = 12 // A domain name pointer
	TypeHINFO QType = 13 // Host information
	TypeMINFO QType = 14 // Mailbox or mail list information
	TypeMX    QType = 15 // Mail exchange
	TypeTXT   QType = 16 // Text strings
	TypeAAAA  QType = 28 // IPv6 address (RFC 3596)
)

// DNS Query Types (QType only) - See RFC 1035 Section 3.2.3
const (
	TypeAXFR     QType = 252 // A request for a transfer of an entire zone
	TypeMAILB    QType = 253 // A request for mailbox-related records (MB, MG, or MR)
	TypeMAILA    QType = 254 // A request for mail agent RRs (Obsolete - see MX)
	TypeASTERISK QType = 255 // A request for all records
)

// DNS Classes - See RFC 1035 Section 3.2.4 and 3.2.5
const (
	ClassIN       QClass = 1   // The Internet
	ClassCS       QClass = 2   // The CSNET class (Obsolete)
	ClassCH       QClass = 3   // The CHAOS class
	ClassHS       QClass = 4   // Hesiod
	ClassASTERISK QClass = 255 // Any class
)

// String returns the string representation of a QType
func (qt QType) String() string {
	switch qt {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeMD:
		return "MD"
	case TypeMF:
		return "MF"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypeMB:
		return "MB"
	case TypeMG:
		return "MG"
	case TypeMR:
		return "MR"
	case TypeNULL:
		return "NULL"
	case TypeWKS:
		return "WKS"
	case TypePTR:
		return "PTR"
	case TypeHINFO:
		return "HINFO"
	case TypeMINFO:
		return "MINFO"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeAXFR:
		return "AXFR"
	case TypeMAILB:
		return "MAILB"
	case TypeMAILA:
		return "MAILA"
	case TypeASTERISK:
		return "*"
	default:
		return "UNKNOWN"
	}
}

// String returns the string representation of a QClass
func (qc QClass) String() string {
	switch qc {
	case ClassIN:
		return "IN"
	case ClassCS:
		return "CS"
	case ClassCH:
		return "CH"
	case ClassHS:
		return "HS"
	case ClassASTERISK:
		return "*"
	default:
		return "UNKNOWN"
	}
}

// Header bitfields according to RFC 1035 Section 4.1.1
type HeaderBitfield uint16

const (
	// QR - Query/Response bit
	HeaderQRQuery    HeaderBitfield = 0 << 15 // Message is a query
	HeaderQRResponse HeaderBitfield = 1 << 15 // Message is a response

	// OPCODE - Operation code
	HeaderOpcodeQuery  HeaderBitfield = 0 << 11 // Standard query
	HeaderOpcodeIQuery HeaderBitfield = 1 << 11 // Inverse query
	HeaderOpcodeStatus HeaderBitfield = 2 << 11 // Server status request

	// Flags
	HeaderAA HeaderBitfield = 1 << 10 // Authoritative Answer
	HeaderTC HeaderBitfield = 1 << 9  // Truncation
	HeaderRD HeaderBitfield = 1 << 8  // Recursion Desired
	HeaderRA HeaderBitfield = 1 << 7  // Recursion Available
	HeaderZ  HeaderBitfield = 0 << 4  // Reserved (must be zero)

	// RCODE - Response code
	HeaderRcodeOK   HeaderBitfield = 0 // No error
	HeaderRcodeFmt  HeaderBitfield = 1 // Format error
	HeaderRcodeSrvr HeaderBitfield = 2 // Server failure
	HeaderRcodeName HeaderBitfield = 3 // Name error
	HeaderRcodeNImpl HeaderBitfield = 4 // Not implemented
	HeaderRcodeRef  HeaderBitfield = 5 // Refused
)
