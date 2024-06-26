package main

import (
	"encoding/binary"
	"log/slog"
)

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

func qNameToDomainName(qName []label) string {
	s := ""
	for i, label := range qName {
		if label.length != 0 && i != 0 {
			s += "."
		}

		s += string(label.data)
	}
	return s
}

// The first two bits are ones.  This allows a pointer to be distinguished
// from a label, since the label must begin with two zero bits because
// labels are restricted to 63 octets or less.  (The 10 and 01 combinations
// are reserved for future use.)  The OFFSET field specifies an offset from
// the start of the message (i.e., the first octet of the ID field in the
// domain header).  A zero offset specifies the first byte of the ID field,
// etc.
func isNamePointer(data []byte, index *int) bool {
	return data[*index]&0xC0 == 0xC0
}

func readQName(data []byte, index *int) []label {
	slog.Debug("Reading QName", "index", *index)

	labels := make([]label, 0)
	for {

		if isNamePointer(data, index) {
			ptr := int(binary.BigEndian.Uint16(data[*index:*index+2]) & 0x3FFF)
			*index += 2
			labels = append(labels, readQName(data, &ptr)...)
			return labels
		}

		l := label{}
		l.length = data[*index]
		*index++
		l.data = data[*index : *index+int(l.length)]
		*index += int(l.length)
		labels = append(labels, l)

		if l.length == 0 {
			break
		}
	}

	return labels
}
