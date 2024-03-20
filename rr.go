package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
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
	hexdumpFormatted("RR buf:", "dump", byteArray)
	return byteArray
}

func (r RR) toString() string {
	s := "\t" + qNameToDomainName(r.Name)
	s += "\tQTYPE: " + r.Type.toString()
	s += "\tQCLASS: " + r.Class.toString()
	s += "\tTTL: " + fmt.Sprint(r.TTL)
	if r.RDLength == 4 {
		s += "\tADDRESS: " + ipv4AddrToString(r.RData)
	} else {
		s += "\tRDLength: " + fmt.Sprint(r.RDLength)
		s += fmt.Sprintf("\tRData: % 02X", r.RData)
	}
	return s
}

func ipv4AddrToString(addr []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
}

func readRR(data []byte, index *int) RR {
	qN := readQName(data, index)
	qT := readQType(data, index)
	qC := readQClass(data, index)

	ttl := int32(binary.BigEndian.Uint32(data[*index : *index+4]))
	*index += 4

	slog.Debug("Reading RR", "Name", qN, "Type", qT, "Class", qC, "TTL", ttl)

	rdl := binary.BigEndian.Uint16(data[*index : *index+2])
	*index += 2

	rdata := data[*index : *index+int(rdl)]
	*index += int(rdl)

	return RR{Name: qN, Type: qT, Class: qC, TTL: ttl, RDLength: rdl, RData: rdata}
}
