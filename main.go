// DNS according to [RFC 1035] DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
//
// [RFC 1035]: https://datatracker.ietf.org/doc/html/rfc1035
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
)

func getNameServerAddress() string { return "198.41.0.4:53" } // "9.9.9.9:53" }  // TODO: implement

func getProtocol() string { return "udp" } // TODO: implement

func debugHexdumpFormatted(msg string, fileName string, data []byte) {
	for index, value := range data {
		if index%8 == 0 {
			msg += " "
			if index%16 == 0 {
				msg += fmt.Sprintln()
			}
		}
		msg += fmt.Sprintf("%02x ", (value))
	}
	msg += fmt.Sprintln()

	f, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.WriteString(msg); err != nil {
		panic(err)
	}

	slog.Debug(fmt.Sprintf("Dumped %d bytes as string to file, plus annotations; appended if file existed.", len(data)), "fileName", fileName)

	debugHexdump(fileName+"raw", data)
}

func debugHexdump(fileName string, data []byte) {
	f, err := os.OpenFile(fileName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}

	defer f.Close()

	if _, err = f.Write(data); err != nil {
		panic(err)
	}

	slog.Debug("Dumped raw bytes to file, overwrote if file existed.", "fileName", fileName)
}

func getMaxMessageSize(protocol string) int {
	if protocol == "tcp" {
		return 4096
	} else if protocol == "udp" {
		return 512
	} else {
		panic("Unknown protocol.")
	}
}

func queryDomain(domain []byte) {
	nameServerAddress := getNameServerAddress()
	protocol := getProtocol()

	conn, err := net.Dial(protocol, nameServerAddress)
	if err != nil {
		fmt.Printf("Error dialing: %v\n", err)
	}

	query := buildQuery(domain)
	id := query.Header.ID
	rawQuery := query.toRawBytes()

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

	debugHexdumpFormatted("Raw query is:", "dump", rawQuery)

	nBytesWritten, err := conn.Write(rawQuery)
	if err != nil {
		fmt.Printf("Error dialing: %v\n", err)
	} else if nBytesWritten != len(rawQuery) {
		fmt.Printf("nBytesWritten (%v) not equal to len(query) (%v)\n", nBytesWritten, len(rawQuery))
	}

	responseBuffer := make([]byte, getMaxMessageSize(protocol)) // UDP capped at 512
	nBytesRecvd, err := conn.Read(responseBuffer)
	if err != nil {
		fmt.Printf("Error receiving: %v\n", err)
	}

	slog.Debug(fmt.Sprintf("Recv'd %d bytes.", nBytesRecvd))
	debugHexdumpFormatted("Recv'd:", "dump", responseBuffer[:nBytesRecvd])

	response := parseResponse(responseBuffer[:nBytesRecvd], protocol)
	if response.Header.ID != id {
		panic("Request and response IDs do not match.")
	}

	response.prettyPrint()
}

func isValidDomain(_ string) bool { return true } // TODO: implement

func setupLogger(level slog.Level) {
	var programLevel = new(slog.LevelVar)
	h := slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			Level:     programLevel,
			AddSource: false,
			ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
				// Remove time from the output for predictable test output.
				if a.Key == slog.TimeKey {
					return slog.Attr{}
				} else {
					return a
				}
			}},
	)
	slog.SetDefault(slog.New(h))
	programLevel.Set(level)
}

func main() {
	setupLogger(slog.LevelInfo)

	if len(os.Args) < 2 {
		panic("Usage: goDNS <domain>")
	}

	domain := os.Args[1]
	if !isValidDomain(domain) {
		panic("Invalid domain.")
	}

	queryDomain([]byte(domain))
}
