package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

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
	hexdumpFormatted("header buf:", "dump", byteArray)
	return byteArray
}

func (h DNSHeader) toString() string {
	s := fmt.Sprintf("\tID: % 02X", h.ID)
	s += fmt.Sprintf("\tMask: % 02X", h.MaskRow)
	s += fmt.Sprintf("\tQDCount: % 02X", h.QDCount)
	s += fmt.Sprintf("\tANCount: % 02X", h.ANCount)
	s += fmt.Sprintf("\tNSCount: % 02X", h.NSCount)
	s += fmt.Sprintf("\tARCount: % 02X", h.ARCount)
	return s
}

func (h DNSHeader) prettyPrint() {
	fmt.Print(h.toString())
}

func getHeaderMaskRow() Header_Bitfield { return HDR_QR_QUERY | HDR_OPCODE_QUERY | HDR_RD }
func getHeaderID() uint16               { return 0xBEEF }

func readHeader(data []byte, index *int) DNSHeader {
	header := DNSHeader{}

	header.ID = binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2
	header.MaskRow = Header_Bitfield(binary.BigEndian.Uint16(data[*index : *index+2]))
	*index += 2
	header.QDCount = binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2
	header.ANCount = binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2
	header.NSCount = binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2
	header.ARCount = binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2

	return header
}
