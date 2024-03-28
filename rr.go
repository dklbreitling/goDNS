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

type RData interface {
	bytes() []byte
	toString() string
}

type IPv4Addr struct {
	a byte
	b byte
	c byte
	d byte
}

func (addr IPv4Addr) bytes() []byte { return []byte{addr.a, addr.b, addr.c, addr.d} }
func (addr IPv4Addr) toString() string {
	return fmt.Sprintf("%d.%d.%d.%d", addr.a, addr.b, addr.c, addr.d)
}

// A 128 bit IPv6 address is encoded in the data portion of an AAAA
// resource record in network byte order (high-order byte first).
// See [RFC 3596:  DNS Extensions to Support IP Version 6].
//
// [RFC 3596:  DNS Extensions to Support IP Version 6]: https://datatracker.ietf.org/doc/html/rfc3596
type IPv6Addr struct {
	data []byte
}

func (addr IPv6Addr) bytes() []byte { return addr.data }

// TODO: make sure it conforms to spec, see [RFC 4291, Sec. 2.2: Text Representation of Addresses].
//
// [RFC 4291, Sec. 2.2: Text Representation of Addresses]: https://datatracker.ietf.org/doc/html/rfc4291#section-2.2
func (addr IPv6Addr) toString() string {
	s := ""

	for index, byte := range addr.data {
		if index%2 == 0 && index != 0 {
			s += ":"
		}
		s += fmt.Sprintf("%02x", byte)
	}

	var cleanAddr string
	var previousAddedChar rune
	var prev rune
	for index, char := range s {
		if index == 0 {
			previousAddedChar = char
			cleanAddr += string(char)
			prev = char
			continue
		}

		if previousAddedChar == ':' && char == '0' {
			prev = char
			continue
		}

		if previousAddedChar == ':' && char == ':' {
			if prev == '0' {
				cleanAddr += "0:"
			}

			prev = char
			continue
		}

		cleanAddr += string(char)
		previousAddedChar = char
		prev = char
	}

	s = cleanAddr
	cleanAddr = ""
	toRemove := make([]bool, len(s))
	once := true
	for index, char := range s {
		if index == 0 || index == 1 {
			continue
		}

		if char == ':' && s[index-1] == '0' && s[index-2] == ':' {
			toRemove[index-1] = true
			if !once {
				toRemove[index-2] = true
			}
			once = false
		}
	}

	for index, char := range s {
		if !toRemove[index] {
			cleanAddr += string(char)
		}

		if index > 1 && s[index] == ':' && s[index-1] == ':' {
			break
		}
	}

	return cleanAddr
}

type NSDName struct {
	name []label
}

func (nsdn NSDName) bytes() []byte {
	// TODO: DRY Domain Names, maybe as a `type DName []label`

	var err error
	buf := new(bytes.Buffer)

	for _, field := range nsdn.name {
		_, err = buf.Write(field.toRawBytes())
		if err != nil {
			panic(fmt.Sprintf("Error converting NSDName %v to raw bytes.\nError: %v\n", nsdn, err))
		}
	}

	return buf.Bytes()
}

func (nsdn NSDName) toString() string { return qNameToDomainName(nsdn.name) }

type OtherRData struct{ data []byte }

func (ord OtherRData) bytes() []byte    { return ord.data }
func (ord OtherRData) toString() string { return fmt.Sprintf("% 02X", ord.data) }

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
	RData    RData
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

	_, err = buf.Write(r.RData.bytes())
	if err != nil {
		panic(fmt.Sprintf("Error converting RR %v to raw bytes.\nError: %v\n", r, err))
	}

	byteArray := buf.Bytes()
	debugHexdumpFormatted("RR buf:", "dump", byteArray)
	return byteArray
}

func (r RR) toString() string {
	s := "\t" + qNameToDomainName(r.Name)
	s += "\tQTYPE: " + r.Type.toString()
	s += "\tQCLASS: " + r.Class.toString()
	s += "\tTTL: " + fmt.Sprint(r.TTL)
	if r.RDLength == 4 && r.Type == QTYPE_A {
		s += "\tADDRESS: " + r.RData.toString()
	} else if r.Type == QTYPE_NS {
		s += "\tNAME: " + r.RData.toString()
	} else if r.RDLength == 16 && r.Type == QTYPE_AAAA {
		s += "\tADDRESS: " + r.RData.toString()
	} else {
		s += "\tRDLength: " + fmt.Sprint(r.RDLength)
		s += "\tRData: " + r.RData.toString()
	}
	return s
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

	var rdata RData
	if qT == QTYPE_A && rdl == 4 {
		rdata = IPv4Addr{a: data[*index], b: data[*index+1], c: data[*index+2], d: data[*index+3]}
		*index += int(rdl)
		slog.Debug("RData IPv4Addr", "rdata", rdata)
	} else if qT == QTYPE_NS {
		rdata = NSDName{name: readQName(data, index)}
		slog.Debug("RData NSDName", "rdata", rdata)
	} else if qT == QTYPE_AAAA {
		rdata = IPv6Addr{data: data[*index : *index+int(rdl)]}
		*index += int(rdl)
		slog.Debug("RData IPv6Addr", "rdata", rdata)
	} else {
		rdata = OtherRData{data: data[*index : *index+int(rdl)]}
		*index += int(rdl)
		slog.Debug("RData Other", "rdata", rdata)
	}

	return RR{Name: qN, Type: qT, Class: qC, TTL: ttl, RDLength: rdl, RData: rdata}
}
