package main

import (
	"encoding/binary"
	"fmt"
	"log/slog"
)

type DNSMessage struct {
	Header     DNSHeader
	Question   []DNSQuestion
	Answer     []RR
	Authority  []RR
	Additional []RR
}

func (m DNSMessage) toRawBytes() []byte {
	byteArray := m.Header.toRawBytes()

	for _, q := range m.Question {
		byteArray = append(byteArray, q.toRawBytes()...)
	}
	for _, a := range [][]RR{m.Answer, m.Authority, m.Additional} {
		for _, value := range a {
			byteArray = append(byteArray, value.toRawBytes()...)
		}
	}
	return byteArray
}

func (m DNSMessage) toString() string {
	s := "; Message:\n"

	s += "; Header:\n"
	s += m.Header.toString()

	fmt.Print(s)
	s = ""

	if m.Header.QDCount > 0 {
		s += "\n; Question:\n"
		for _, q := range m.Question {
			s += q.toString()
			fmt.Print(s + "\n")
			s = ""
		}

	}

	fmt.Print(s)
	s = ""

	if m.Header.ANCount > 0 {
		s += "\n; Answer:\n"
		for _, answerRR := range m.Answer {
			s += answerRR.toString()
			fmt.Print(s + "\n")
			s = ""
		}

	}

	if m.Header.NSCount > 0 {
		s += "\n; Authority:\n"
		for _, authorityRR := range m.Authority {
			s += authorityRR.toString()
			fmt.Print(s + "\n")
			s = ""
		}

	}

	if m.Header.ARCount > 0 {
		s += "\n; Additional:\n"
		for _, additionalRR := range m.Additional {
			s += additionalRR.toString()
			fmt.Print(s + "\n")
			s = ""
		}

	}

	fmt.Println()
	return s + "\n"
}

func (m DNSMessage) prettyPrint() {
	fmt.Print(m.toString())
}

func buildQuery(domain []byte) DNSMessage {
	header := DNSHeader{ID: getHeaderID(), MaskRow: getHeaderMaskRow(), QDCount: 1, ANCount: 0, NSCount: 0, ARCount: 0}
	debugHexdumpFormatted("Raw header in build:", "dump", header.toRawBytes())
	question := buildQuestion(domain)
	return DNSMessage{Header: header, Question: []DNSQuestion{question}, Answer: nil, Authority: nil, Additional: nil}
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

func readMessage(data []byte, index *int) DNSMessage {
	if index == nil {
		i := 0
		index = &i
		slog.Debug("Index nil in readMessage, setting to zero.")
	}

	header := readHeader(data, index)

	var question []DNSQuestion
	for range header.QDCount {
		question = append(question, readQuestion(data, index))
	}

	var answer []RR
	slog.Debug("Reading ANCount Resource Records.", "ANCount", header.ANCount)
	for range header.ANCount {
		answer = append(answer, readRR(data, index))
	}

	slog.Debug("Reading NSCount Resource Records.", "NSCount", header.NSCount)
	var authority []RR
	for range header.NSCount {
		authority = append(authority, readRR(data, index))
	}

	slog.Debug("Reading ARCount Resource Records.", "ARCount", header.ARCount)
	var additional []RR
	for range header.ARCount {
		additional = append(additional, readRR(data, index))
	}

	return DNSMessage{Header: header, Question: question, Answer: answer, Authority: authority, Additional: additional}
}

func parseTcpResponse(responseBuffer []byte) DNSMessage {
	index := 0
	length := binary.BigEndian.Uint16(responseBuffer[index : index+2])
	index += 2
	if !validLength(length) {
		panic("Invalid response length field.")
	}

	// the two length bytes are skipped to facilitate parsing
	// of UDP and TCP without special cases
	packet := responseBuffer[index:]
	debugHexdumpFormatted("packet", "dumpresponse", packet)

	index = 0
	return readMessage(packet, &index)

}

func parseUdpResponse(responseBuffer []byte) DNSMessage {
	return readMessage(responseBuffer, nil)
}
