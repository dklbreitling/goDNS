// DNS according to [RFC 1035] DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
package goDNS

import (
	"bytes"
)

// See [Sec. 3.2.2 TYPE Values] and [Sec. 3.2.3 QTYPE Values]
//
// [Sec. 3.2.2 TYPE Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
// [Sec. 3.2.3 QTYPE Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
type QType uint16

const (
	QType_A     QType = iota + 1 // a host address
	QType_NS                     // an authoritative name server
	QType_MD                     // a mail destination (Obsolete - use MX)
	QType_MF                     // a mail forwarder (Obsolete - use MX)
	QType_CNAME                  // the canonical name for an alias
	QType_SOA                    // marks the start of a zone of authority
	QType_MB                     // a mailbox domain name (EXPERIMENTAL)
	QType_MG                     // a mail group member (EXPERIMENTAL)
	QType_MR                     // a mail rename domain name  (EXPERIMENTAL)
	QType_NULL                   // a null RR (EXPERIMENTAL)
	QType_WKS                    // a well known service description
	QType_PTR                    // a domain name pointer
	QType_HINFO                  // host information
	QType_MINFO                  // mailbox or mail list information
	QType_MX                     // mail exchange
	QType_TXT                    // text strings
)
const (
	QTYPE_AXFR     = iota + 252 // a request for a transfer of an entire zone
	QTYPE_MAILB                 // a request for mailbox-related records (MB, MG, or MR)
	QTYPE_MAILA                 // a request for mail agent RRs (Obsolete - see MX)
	QTYPE_ASTERISK              // a request for all records (symbol "*" in RFC)
)

// See [Sec. 3.2.4 CLASS Values] and [Sec. 3.2.5 QCLASS Values]
//
// [Sec. 3.2.4 CLASS Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
// [Sec. 3.2.5 QCLASS Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
type QClass uint16

const (
	QCLASS_IN       QClass = iota + 1 // the Internet
	QCLASS_CS                         // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	QCLASS_CH                         // the CHAOS class
	QCLASS_HS                         // Hesiod [Dyer 87]
	QCLASS_ASTERISK = 255             // any class (symbol "*" in RFC)
)

/* https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4 Size limits
 *
 * Various objects and parameters in the DNS have size limits.  They are
 * listed below.  Some could be easily changed, others are more
 * fundamental.
 *
 * labels          63 octets or less
 *
 * names           255 octets or less
 *
 * TTL             positive values of a signed 32 bit number.s
 *
 * UDP messages    512 octets or less
 */

// See [Sec. 3.2 RR definitions]. Transmitted in big endian, i.e. network order (see [Sec. 2.3.2 Data Transmission Order]).
//
// [Sec. 2.3.2 Data Transmission Order]: https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.2
// [Sec. 3.2 RR definitions]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2
type RR struct {
	Name     bytes.Buffer
	Type     QType  // subset of QType up to TXT (=16)
	Class    QClass // subset of QClass up to HS (=4)
	TTL      int32  // positive int32
	RDLength uint16
	RData    bytes.Buffer
}

// Bitfields used in header, see [Sec. 4.1.1 Header section format].
//
// [Sec. 4.1.1 Header section format]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type Header_Bitfield uint16

const (
	HDR_QR_QUERY      Header_Bitfield = 0 << 15 // Message is a query
	HDR_QR_RESPONSE   Header_Bitfield = 1 << 15 // Message is a response
	HDR_OPCODE_QUERY  Header_Bitfield = 0 << 11 // Standard query type, copied into response
	HDR_OPCODE_IQUERY Header_Bitfield = 1 << 11 // Inverse query type, copied into respone
	HDR_OPCODE_Status Header_Bitfield = 2 << 11 // Server status request query type, copied into response
	HDR_AA            Header_Bitfield = 1 << 10 // Authoritative Answer - this bit is valid in responses, and specifies that the responding name server is an authority for the domain name in question section. Note that the contents of the answer section may have multiple owner names because of aliases.  The AA bit corresponds to the name which matches the query name, or the first owner name in the answer section.
	HDR_TC            Header_Bitfield = 1 << 9  // TrunCation - specifies that this message was truncated due to length greater than that permitted on the transmission channel.
	HDR_RD            Header_Bitfield = 1 << 8  // Recursion Desired - this bit may be set in a query and is copied into the response.  If RD is set, it directs the name server to pursue the query recursively. Recursive query support is optional.
	HDR_RA            Header_Bitfield = 1 << 7  // Recursion Available - this be is set or cleared in a response, and denotes whether recursive query support is available in the name server.
	HDR_Z             Header_Bitfield = 0 << 4  // Reserved for future use.  Must be zero in all queries and responses.
	HDR_RCODE_OK      Header_Bitfield = 0       // No error condition
	HDR_RCODE_FMT     Header_Bitfield = 1       // Format error - The name server was unable to interpret the query.
	HDR_RCODE_SRVR    Header_Bitfield = 2       // Server failure - The name server was unable to process this query due to a problem with the name server.
	HDR_RCODE_NAME    Header_Bitfield = 3       // Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
	HDR_RCODE_NIMPL   Header_Bitfield = 4       // Not Implemented - The name server does not support the requested kind of query.
	HDR_RCODE_REF     Header_Bitfield = 5       // Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation (e.g., zone transfer) for particular data.
)

type BGPHeader struct {
	ID      uint16
	MaskRow uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type BGPQuestion struct{}
type BGPAnswer struct{}
type BGPAuthority struct{}
type BGPAdditional struct{}

type BGPMessage struct {
	Header     BGPHeader
	Question   BGPQuestion
	Answer     []RR
	Authority  []RR
	Additional []RR
}

func main() {
}
