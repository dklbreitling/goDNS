package main

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

func readQNameFromBytes(data []byte, index *int) []label {
	labels := make([]label, 0)
	for {
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
