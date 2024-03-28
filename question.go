package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
)

// See [Sec. 3.2.2 TYPE Values] and [Sec. 3.2.3 QType Values]
//
// [Sec. 3.2.2 TYPE Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.2
// [Sec. 3.2.3 QType Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.3
type QType uint16

// See [Sec. 3.2.4 CLASS Values] and [Sec. 3.2.5 QClass Values]
//
// [Sec. 3.2.4 CLASS Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.4
// [Sec. 3.2.5 QClass Values]: https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.5
type QClass uint16

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
	debugHexdumpFormatted("header buf:", "dump", byteArray)
	return byteArray
}

func (q DNSQuestion) toString() string {
	s := "\t" + qNameToDomainName(q.QNAME)
	s += "\tQTYPE: " + q.QTYPE.toString()
	s += "\tQCLASS: " + q.QCLASS.toString()
	return s
}

func (q DNSQuestion) prettyPrint() {
	fmt.Print(q.toString())
}

func buildQuestion(domain []byte) DNSQuestion {
	QName := splitDomainNameIntoLabels(domain)
	return DNSQuestion{QNAME: QName, QTYPE: QTYPE_A, QCLASS: QCLASS_IN}
}

func readQType(data []byte, index *int) QType {
	qt := QType(binary.BigEndian.Uint16(data[*index : *index+2]))
	*index += 2
	return qt
}

func readQClass(data []byte, index *int) QClass {
	qc := QClass(binary.BigEndian.Uint16(data[*index : *index+2]))
	*index += 2
	return qc
}

func readQuestion(data []byte, index *int) DNSQuestion {
	if index == nil {
		i := 0
		index = &i
		slog.Debug("Index nil in readQuestionFromBytes, setting to zero.")
	}

	question := DNSQuestion{}

	question.QNAME = readQName(data, index)
	question.QTYPE = readQType(data, index)
	question.QCLASS = readQClass(data, index)
	return question
}
