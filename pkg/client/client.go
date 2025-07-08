// Package client provides a DNS client implementation
package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"time"

	"dklbreitling/goDNS/internal/config"
	"dklbreitling/goDNS/pkg/dns"
	"dklbreitling/goDNS/pkg/records"
)

// Client represents a DNS client
type Client struct {
	config *config.Config
	logger *slog.Logger
}

// New creates a new DNS client with the given configuration
func New(cfg *config.Config, logger *slog.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	
	return &Client{
		config: cfg,
		logger: logger,
	}, nil
}

// Query performs a DNS query for the given domain and record type
func (c *Client) Query(domain string, qtype dns.QType) (*dns.Message, error) {
	// Validate domain
	if err := dns.ValidateDomain(domain); err != nil {
		return nil, fmt.Errorf("invalid domain: %w", err)
	}
	
	// Build query message
	query, err := c.buildQuery(domain, qtype)
	if err != nil {
		return nil, fmt.Errorf("failed to build query: %w", err)
	}
	
	// Send query and receive response
	response, err := c.sendQuery(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query: %w", err)
	}
	
	return response, nil
}

// buildQuery creates a DNS query message
func (c *Client) buildQuery(domain string, qtype dns.QType) (*dns.Message, error) {
	// Generate random query ID
	queryID := uint16(rand.Intn(65536))
	
	// Build header
	flags := dns.HeaderQRQuery | dns.HeaderOpcodeQuery
	if c.config.RecursionDesired {
		flags |= dns.HeaderRD
	}
	
	header := dns.Header{
		ID:      queryID,
		Flags:   flags,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}
	
	// Build question
	question := dns.Question{
		Name:  dns.StringToLabels(domain),
		Type:  qtype,
		Class: dns.ClassIN,
	}
	
	return &dns.Message{
		Header:     header,
		Question:   []dns.Question{question},
		Answer:     nil,
		Authority:  nil,
		Additional: nil,
	}, nil
}

// sendQuery sends a DNS query and returns the response
func (c *Client) sendQuery(query *dns.Message) (*dns.Message, error) {
	// Convert query to bytes
	queryBytes, err := query.ToBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize query: %w", err)
	}
	
	// Add TCP length prefix if needed
	if c.config.Protocol == "tcp" {
		length := uint16(len(queryBytes))
		buf := new(bytes.Buffer)
		if err := binary.Write(buf, binary.BigEndian, length); err != nil {
			return nil, fmt.Errorf("failed to add TCP length prefix: %w", err)
		}
		queryBytes = append(buf.Bytes(), queryBytes...)
	}
	
	c.logger.Debug("Sending DNS query", "size", len(queryBytes), "protocol", c.config.Protocol)
	
	// Connect to DNS server
	conn, err := net.DialTimeout(c.config.Protocol, c.config.NameServer, c.config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to DNS server: %w", err)
	}
	defer conn.Close()
	
	// Set write deadline
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}
	
	// Send query
	n, err := conn.Write(queryBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to write query: %w", err)
	}
	if n != len(queryBytes) {
		return nil, fmt.Errorf("incomplete write: wrote %d bytes, expected %d", n, len(queryBytes))
	}
	
	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(c.config.Timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}
	
	// Read response
	responseBytes := make([]byte, c.config.GetMaxMessageSize())
	n, err = conn.Read(responseBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}
	responseBytes = responseBytes[:n]
	
	c.logger.Debug("Received DNS response", "size", n)
	
	// Parse response
	response, err := c.parseResponse(responseBytes, query.Header.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	
	return response, nil
}

// parseResponse parses a DNS response from wire format
func (c *Client) parseResponse(data []byte, expectedID uint16) (*dns.Message, error) {
	// Handle TCP length prefix
	if c.config.Protocol == "tcp" {
		if len(data) < 2 {
			return nil, fmt.Errorf("TCP response too short for length prefix")
		}
		length := binary.BigEndian.Uint16(data[:2])
		if int(length) != len(data)-2 {
			return nil, fmt.Errorf("TCP length mismatch: expected %d, got %d", length, len(data)-2)
		}
		data = data[2:] // Remove length prefix
	}
	
	if len(data) < 12 {
		return nil, fmt.Errorf("DNS response too short: %d bytes", len(data))
	}
	
	index := 0
	
	// Parse header
	header := dns.Header{
		ID:      binary.BigEndian.Uint16(data[index : index+2]),
		Flags:   dns.HeaderBitfield(binary.BigEndian.Uint16(data[index+2 : index+4])),
		QDCount: binary.BigEndian.Uint16(data[index+4 : index+6]),
		ANCount: binary.BigEndian.Uint16(data[index+6 : index+8]),
		NSCount: binary.BigEndian.Uint16(data[index+8 : index+10]),
		ARCount: binary.BigEndian.Uint16(data[index+10 : index+12]),
	}
	index += 12
	
	// Verify query ID matches
	if header.ID != expectedID {
		return nil, fmt.Errorf("response ID %d does not match query ID %d", header.ID, expectedID)
	}
	
	message := &dns.Message{
		Header:     header,
		Question:   make([]dns.Question, header.QDCount),
		Answer:     make([]dns.ResourceRecord, header.ANCount),
		Authority:  make([]dns.ResourceRecord, header.NSCount),
		Additional: make([]dns.ResourceRecord, header.ARCount),
	}
	
	// Parse questions (should match what we sent)
	for i := uint16(0); i < header.QDCount; i++ {
		question, newIndex, err := c.parseQuestion(data, index)
		if err != nil {
			return nil, fmt.Errorf("failed to parse question %d: %w", i, err)
		}
		message.Question[i] = question
		index = newIndex
	}
	
	// Parse answer records
	for i := uint16(0); i < header.ANCount; i++ {
		rr, newIndex, err := c.parseResourceRecord(data, index)
		if err != nil {
			return nil, fmt.Errorf("failed to parse answer record %d: %w", i, err)
		}
		message.Answer[i] = rr
		index = newIndex
	}
	
	// Parse authority records
	for i := uint16(0); i < header.NSCount; i++ {
		rr, newIndex, err := c.parseResourceRecord(data, index)
		if err != nil {
			return nil, fmt.Errorf("failed to parse authority record %d: %w", i, err)
		}
		message.Authority[i] = rr
		index = newIndex
	}
	
	// Parse additional records
	for i := uint16(0); i < header.ARCount; i++ {
		rr, newIndex, err := c.parseResourceRecord(data, index)
		if err != nil {
			return nil, fmt.Errorf("failed to parse additional record %d: %w", i, err)
		}
		message.Additional[i] = rr
		index = newIndex
	}
	
	return message, nil
}

// parseQuestion parses a DNS question from wire format
func (c *Client) parseQuestion(data []byte, index int) (dns.Question, int, error) {
	// Parse name labels
	labels, newIndex, err := c.parseLabels(data, index)
	if err != nil {
		return dns.Question{}, 0, fmt.Errorf("failed to parse question name: %w", err)
	}
	
	if newIndex+4 > len(data) {
		return dns.Question{}, 0, fmt.Errorf("question data truncated")
	}
	
	qtype := dns.QType(binary.BigEndian.Uint16(data[newIndex : newIndex+2]))
	qclass := dns.QClass(binary.BigEndian.Uint16(data[newIndex+2 : newIndex+4]))
	
	return dns.Question{
		Name:  labels,
		Type:  qtype,
		Class: qclass,
	}, newIndex + 4, nil
}

// parseResourceRecord parses a DNS resource record from wire format
func (c *Client) parseResourceRecord(data []byte, index int) (dns.ResourceRecord, int, error) {
	// Parse name labels
	labels, newIndex, err := c.parseLabels(data, index)
	if err != nil {
		return dns.ResourceRecord{}, 0, fmt.Errorf("failed to parse RR name: %w", err)
	}
	
	if newIndex+10 > len(data) {
		return dns.ResourceRecord{}, 0, fmt.Errorf("RR header data truncated")
	}
	
	rrType := dns.QType(binary.BigEndian.Uint16(data[newIndex : newIndex+2]))
	rrClass := dns.QClass(binary.BigEndian.Uint16(data[newIndex+2 : newIndex+4]))
	ttl := int32(binary.BigEndian.Uint32(data[newIndex+4 : newIndex+8]))
	rdLength := binary.BigEndian.Uint16(data[newIndex+8 : newIndex+10])
	newIndex += 10
	
	if newIndex+int(rdLength) > len(data) {
		return dns.ResourceRecord{}, 0, fmt.Errorf("RR data truncated")
	}
	
	// Parse resource data based on type
	var rdata dns.ResourceData
	rdataBytes := data[newIndex : newIndex+int(rdLength)]
	
	switch rrType {
	case dns.TypeA:
		if len(rdataBytes) != 4 {
			return dns.ResourceRecord{}, 0, fmt.Errorf("invalid A record length: %d", len(rdataBytes))
		}
		ip := net.IPv4(rdataBytes[0], rdataBytes[1], rdataBytes[2], rdataBytes[3])
		if aRecord, err := records.NewARecord(ip); err == nil {
			rdata = aRecord
		} else {
			rdata = records.NewGenericRecord(rrType, rdataBytes)
		}
	case dns.TypeAAAA:
		if len(rdataBytes) != 16 {
			return dns.ResourceRecord{}, 0, fmt.Errorf("invalid AAAA record length: %d", len(rdataBytes))
		}
		ip := net.IP(rdataBytes)
		if aaaaRecord, err := records.NewAAAARecord(ip); err == nil {
			rdata = aaaaRecord
		} else {
			rdata = records.NewGenericRecord(rrType, rdataBytes)
		}
	case dns.TypeNS:
		nsLabels, _, err := c.parseLabels(data, newIndex)
		if err != nil {
			rdata = records.NewGenericRecord(rrType, rdataBytes)
		} else {
			rdata = records.NewNSRecord(nsLabels)
		}
	default:
		rdata = records.NewGenericRecord(rrType, rdataBytes)
	}
	
	return dns.ResourceRecord{
		Name:     labels,
		Type:     rrType,
		Class:    rrClass,
		TTL:      ttl,
		RDLength: rdLength,
		RData:    rdata,
	}, newIndex + int(rdLength), nil
}

// parseLabels parses DNS labels from wire format, handling compression
func (c *Client) parseLabels(data []byte, index int) ([]dns.Label, int, error) {
	var labels []dns.Label
	originalIndex := index
	followed := false
	
	for index < len(data) {
		length := data[index]
		
		// Check for compression pointer
		if length&0xC0 == 0xC0 {
			if index+1 >= len(data) {
				return nil, 0, fmt.Errorf("compression pointer truncated")
			}
			pointer := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3FFF)
			if pointer >= len(data) {
				return nil, 0, fmt.Errorf("invalid compression pointer: %d", pointer)
			}
			
			// Follow the pointer recursively
			compressedLabels, _, err := c.parseLabels(data, pointer)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to follow compression pointer: %w", err)
			}
			labels = append(labels, compressedLabels...)
			
			if !followed {
				return labels, index + 2, nil
			}
			return labels, originalIndex + 2, nil
		}
		
		// Regular label
		if length == 0 {
			// Null terminator
			labels = append(labels, dns.Label{Length: 0, Data: nil})
			if !followed {
				return labels, index + 1, nil
			}
			return labels, originalIndex + 1, nil
		}
		
		if index+1+int(length) > len(data) {
			return nil, 0, fmt.Errorf("label data truncated")
		}
		
		label := dns.Label{
			Length: length,
			Data:   make([]byte, length),
		}
		copy(label.Data, data[index+1:index+1+int(length)])
		labels = append(labels, label)
		
		index += 1 + int(length)
	}
	
	return nil, 0, fmt.Errorf("labels not properly terminated")
}
