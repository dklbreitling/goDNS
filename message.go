package main

import (
	"encoding/binary"
	"fmt"
)

type DNSMessage struct {
	Header     DNSHeader
	Question   DNSQuestion
	Answer     []RR
	Authority  []RR
	Additional []RR
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
	// hexdump("RR buf:", byteArray)
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

func (m DNSMessage) toString() string {
	s := "Message:\n"
	s += m.Header.toString()
	s += m.Question.toString()
	return s
}

func (m DNSMessage) prettyPrint() {
	fmt.Print(m.toString())
}

func buildQuery(domain []byte) DNSMessage {
	header := DNSHeader{ID: getHeaderID(), MaskRow: getHeaderMaskRow(), QDCount: 1, ANCount: 0, NSCount: 0, ARCount: 0}
	hexdumpFormatted("Raw header in build:", "dump", header.toRawBytes())
	question := buildQuestion(domain)
	return DNSMessage{Header: header, Question: question, Answer: nil, Authority: nil, Additional: nil}
}

func parseResponse(responseBuffer []byte, protocol string) DNSMessage {
	if protocol == "tcp" {
		return parseTcpResponse(responseBuffer)
	} else if protocol == "udp" {
		return parseUdpResponse(responseBuffer)
	} else {
		panic("Unknown protocol.")
	}
}

func validLength(_ uint16) bool { return true }

func parseTcpResponse(responseBuffer []byte) DNSMessage {
	index := 0

	length := binary.BigEndian.Uint16(responseBuffer[index : index+2])
	index += 2
	if !validLength(length) {
		panic("Invalid response length field.")
	}
	header := readHeaderFromBytes(responseBuffer, &index)
	question := readQuestionFromBytes(responseBuffer, &index)
	return DNSMessage{Header: header, Question: question}

}

func parseUdpResponse(responseBuffer []byte) DNSMessage {
	panic("Not implemented.")
}
