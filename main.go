// DNS according to [RFC 1035] DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// See [Sec. 3.2.2 TYPE Values] and [Sec. 3.2.3 QType Values]
//
// [Sec. 3.2.2 TYPE Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
// [Sec. 3.2.3 QType Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
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

// See [Sec. 3.2.4 CLASS Values] and [Sec. 3.2.5 QClass Values]
//
// [Sec. 3.2.4 CLASS Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
// [Sec. 3.2.5 QClass Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
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
	Name     []label
	Type     QType  // subset of QType up to TXT (=16)
	Class    QClass // subset of QClass up to HS (=4)
	TTL      int32  // positive int32
	RDLength uint16
	RData    []byte
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

// See [Sec. 4.1.1 Header section format].
//
// [Sec. 4.1.1 Header section format]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
type DNSHeader struct {
	// A 16 bit identifier assigned by the program that
	// generates any kind of query.  This identifier is copied
	// the corresponding reply and can be used by the requester
	// to match up replies to outstanding queries.
	ID      uint16
	MaskRow Header_Bitfield
	QDCount uint16 // the number of entries in the question section
	ANCount uint16 // the number of resource records in the answer section
	NSCount uint16 // the number of name server resource records in the authority records section
	ARCount uint16 // the number of resource records in the additional records section
}

// Domain names in messages are expressed in terms of a sequence of labels.
// Each label is represented as a one octet length field followed by that
// number of octets.  Since every domain name ends with the null label of
// the root, a domain name is terminated by a length byte of zero.  The
// high order two bits of every length octet must be zero, and the
// remaining six bits of the length field limit the label to 63 octets or
// less.
//
// To simplify implementations, the total length of a domain name (i.e.,
// label octets and label length octets) is restricted to 255 octets or
// less.
//
// Although labels can contain any 8 bit values in octets that make up a
// label, it is strongly recommended that labels follow the preferred
// syntax described elsewhere in this memo, which is compatible with
// existing host naming conventions.  Name servers and resolvers must
// compare labels in a case-insensitive manner (i.e., A=a), assuming ASCII
// with zero parity.  Non-alphabetic codes must match exactly.
//
// 63 octets or less
//
// Example: www.google.com
//
// www -> hex 03 77 77 77
//
// google -> hex 06 67 6f 6f 67 6c 65
//
// com -> hex 03 63 6f 6d
//
// trailing -> hex 00
type label struct {
	length byte
	data   []byte
}

func (l label) toRawBytes() []byte {
	return append([]byte{l.length}, l.data...)
}

// The question section is used to carry the "question" in most queries,
// i.e., the parameters that define what is being asked.  The section
// contains QDCOUNT (usually 1) entries. See [Sec. 4.1.2 Question section format].
//
// [Sec. 4.1.2 Question section format]: https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
type DNSQuestion struct {
	// A domain name represented as a sequence of labels, where
	// each label consists of a length octet followed by that
	// number of octets.  The domain name terminates with the
	// zero length octet for the null label of the root.  Note
	// that this field may be an odd number of octets; no
	// padding is used.
	//
	// 255 octets or less
	QNAME []label
	// A two octet code which specifies the type of the query.
	// The values for this field include all codes valid for a
	// TYPE field, together with some more general codes which
	// can match more than one type of RR.
	QTYPE QType
	// A two octet code that specifies the class of the query.
	// For example, the QCLASS field is IN for the Internet.
	QCLASS QClass
}

type DNSAnswer struct{}
type DNSAuthority struct{}
type DNSAdditional struct{}

type DNSMessage struct {
	Header     DNSHeader
	Question   DNSQuestion
	Answer     []RR
	Authority  []RR
	Additional []RR
}

func (r RR) toRawBytes() []byte {
	var err error
	buf := new(bytes.Buffer)

	for _, field := range r.Name {
		_, err = buf.Write(field.toRawBytes())
		if err != nil {
			panic(fmt.Sprintf("Error converting RR %v to raw bytes.\nError: %v\n", r, err))
		}
	}

	for _, field := range []any{r.Name, r.Type, r.Class, r.TTL, r.RDLength, r.RData} {
		err = binary.Write(buf, binary.BigEndian, field)
		if err != nil {
			panic(fmt.Sprintf("Error converting RR %v to raw bytes.\nError: %v\n", r, err))
		}
	}

	_, err = buf.Write(r.RData)
	if err != nil {
		panic(fmt.Sprintf("Error converting RR %v to raw bytes.\nError: %v\n", r, err))
	}

	byteArray := buf.Bytes()
	hexdumpStyleBytePrint("RR buf:", byteArray)
	return byteArray
}

func (h DNSHeader) toRawBytes() []byte {
	buf := new(bytes.Buffer)
	var err error
	for _, field := range []any{h.ID, h.MaskRow, h.QDCount, h.ANCount, h.NSCount, h.ARCount} {
		err = binary.Write(buf, binary.BigEndian, field)
		if err != nil {
			panic(fmt.Sprintf("Error converting header %v to raw bytes.\nError: %v\n", h, err))
		}
	}

	byteArray := buf.Bytes()
	hexdumpStyleBytePrint("header buf:", byteArray)
	return byteArray
}

func (q DNSQuestion) toRawBytes() []byte {
	var err error
	buf := new(bytes.Buffer)

	for _, field := range q.QNAME {
		_, err = buf.Write(field.toRawBytes())
		if err != nil {
			panic(fmt.Sprintf("Error converting question %v to raw bytes.\nError: %v\n", q, err))
		}
	}

	for _, field := range []any{q.QTYPE, q.QCLASS} {
		err = binary.Write(buf, binary.BigEndian, field)
		if err != nil {
			panic(fmt.Sprintf("Error converting question %v to raw bytes.\nError: %v\n", q, err))
		}
	}

	byteArray := buf.Bytes()
	hexdumpStyleBytePrint("header buf:", byteArray)
	return byteArray
}

func (m DNSMessage) toRawBytes() []byte {
	// buf := new(bytes.Buffer)
	// var err error
	// for _, field := range []any{m.Header, m.Question, m.Answer, m.Authority, m.Additional} {
	// 	err = binary.Write(buf, binary.BigEndian, field)
	// 	if err != nil {
	// 		panic(fmt.Sprintf("Error converting message %v to raw bytes.\nError: %v\n", m, err))
	// 	}
	// }
	// byteArray := buf.Bytes()
	// hexdumpStyleBytePrint("RR buf:", byteArray)
	// return byteArray
	// return []byte(fmt.Sprintf("%x", m))

	byteArray := append(m.Header.toRawBytes(), m.Question.toRawBytes()...)
	for _, a := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, value := range a {
			byteArray = append(byteArray, value.toRawBytes()...)
		}
	}
	return byteArray
}

func getHeaderID() uint16 { return 0xBEEF }

func getNameServerAddress() string { return "9.9.9.9:53" }

func getProtocol() string { return "tcp" }

func getHeaderMaskRow() Header_Bitfield { return HDR_QR_QUERY | HDR_OPCODE_QUERY | HDR_RD }

func splitDomainNameIntoLabels(domain []byte) []label {
	subdomains := make([][]byte, 0)
	previousStop := 0
	for index, char := range domain {
		if char == byte(0x2E) { // ascii '.'
			subdomains = append(subdomains, domain[previousStop:index])
			previousStop = index + 1
		} else if index == len(domain)-1 {
			subdomains = append(subdomains, domain[previousStop:])
		}
	}

	labels := make([]label, len(subdomains)+1)
	for index, subdomain := range subdomains {
		labels[index] = label{length: byte(len(subdomain)), data: subdomain}
	}
	labels[len(subdomains)] = label{length: 0, data: nil}

	return labels
}

func buildQuestion(domain []byte) DNSQuestion {
	QName := splitDomainNameIntoLabels(domain)
	return DNSQuestion{QNAME: QName, QTYPE: QType_A, QCLASS: QCLASS_IN}
}

func buildQuery(domain []byte) DNSMessage {
	header := DNSHeader{ID: getHeaderID(), MaskRow: getHeaderMaskRow(), QDCount: 1, ANCount: 0, NSCount: 0, ARCount: 0}
	hexdumpStyleBytePrint("Raw header in build:", header.toRawBytes())
	question := buildQuestion(domain)
	return DNSMessage{Header: header, Question: question, Answer: nil, Authority: nil, Additional: nil}
}

func hexdumpStyleBytePrint(msg string, byteArray []byte) {
	fmt.Printf(msg)
	for index, value := range byteArray {
		if index%8 == 0 {
			fmt.Printf(" ")
			if index%16 == 0 {
				fmt.Println()
			}
		}
		fmt.Printf("%02x ", (value))
	}
	fmt.Println()
}

func queryDomain(domain []byte) {
	nameServerAddress := getNameServerAddress()
	protocol := getProtocol()

	conn, err := net.Dial(protocol, nameServerAddress)
	if err != nil {
		fmt.Printf("Error dialing: %v\n", err)
	}

	query := buildQuery(domain)
	rawQuery := query.toRawBytes()

	fmt.Printf("Query is:\n%v\n", query)

	// Messages sent over TCP connections use server port 53 (decimal).  The
	// message is prefixed with a two byte length field which gives the message
	// length, excluding the two byte length field.  This length field allows
	// the low-level processing to assemble a complete message before beginning
	// to parse it.
	if protocol == "tcp" {
		rawLength := uint16(len(rawQuery))
		buf := new(bytes.Buffer)
		err = binary.Write(buf, binary.BigEndian, rawLength)
		if err != nil {
			panic(fmt.Sprintf("Error prepending length to raw query.\nError: %v\n", err))
		}
		rawQuery = append(buf.Bytes(), rawQuery...)
	}

	// fmt.Printf("Raw query is:")
	// for index, value := range rawQuery {
	// 	if index%8 == 0 {
	// 		fmt.Printf(" ")
	// 		if index%16 == 0 {
	// 			fmt.Println()
	// 		}
	// 	}
	// 	fmt.Printf("%x ", value)
	// }
	// fmt.Println()

	hexdumpStyleBytePrint("Raw query is:", rawQuery)
	// hexdumpStyleBytePrint("Raw header is:", query.Header.toRawBytes())
	// hexdumpStyleBytePrint("Raw question is:", query.Question.toRawBytes())

	// fmt.Println("Test print 0xBEEF:")
	// xBeef := 0xBEEF
	// fmt.Printf("0xBEEF >> 8: %X, 0xBEEF & 0xFF: %X, uint8(0xBEEF): %X, uint8(0xBEEF & xFF): %X\n", xBeef>>8, xBeef&0xFF, uint8(xBeef), uint8(xBeef&0xFF))

	// fmt.Printf("raw header: %x\n", query.Header.toRawBytes())
	// fmt.Printf("raw question: %x\n", query.Question.toRawBytes())

	nBytesWritten, err := conn.Write(rawQuery)
	if err != nil {
		fmt.Printf("Error dialing: %v\n", err)
	} else if nBytesWritten != len(rawQuery) {
		fmt.Printf("nBytesWritten (%v) not equal to len(query) (%v)\n", nBytesWritten, len(rawQuery))
	}

	responseBuffer := make([]byte, 4*1024) // UDP capped at 512
	conn.SetReadDeadline(time.Now().Add(time.Minute))
	nBytesRecvd, err := conn.Read(responseBuffer)
	if err != nil {
		fmt.Printf("Error receiving: %v\n", err)
	}

	fmt.Printf("Recv'd %d bytes\n", nBytesRecvd)
	hexdumpStyleBytePrint("Recv'd:", responseBuffer[:nBytesRecvd])
}

func main() {
	// _header := []byte("")

	// 	conn, err := net.Dial("tcp", "9.9.9.9:53")
	// 	if err != nil {
	// 		fmt.Printf("Error dialing: %v\n", err)
	// 	}
	// 	_, err = conn.Write([]byte("Hello"))
	// 	if err != nil {
	// 		fmt.Printf("Error sending: %v\n", err)
	// 	}
	// 	buffer := make([]byte, 1024)
	// 	recv_len, err := conn.Read(buffer)
	// 	if err != nil {
	// 		fmt.Printf("Error receiving: %v\n", err)
	// 	}
	// 	fmt.Println("Recv'd: ", string(buffer[recv_len]))

	// conn, err := net.Dial("tcp", "google.com:80")
	// if err != nil {
	// 	fmt.Printf("Error dialing: %v\n", err)
	// }

	// fmt.Fprintf(conn, "GET / HTTP/1.0\r\n\r\n")
	// status, err := bufio.NewReader(conn).ReadString('\n')
	// fmt.Println("status: ", status)
	// buffer := make([]byte, 1024*1024)
	// recv_len, err := conn.Read(buffer)
	// if err != nil {
	// 	fmt.Printf("Error receiving: %v\n", err)
	// }
	// fmt.Printf("Recv'd %d bytes\n", recv_len)
	// fmt.Println("Recv'd: ", buffer[recv_len])

	// defer conn.Close()

	queryDomain([]byte("www.google.com"))
}
