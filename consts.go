package main

const (
	QTYPE_A     QType = iota + 1 // a host address
	QTYPE_NS                     // an authoritative name server
	QTYPE_MD                     // a mail destination (Obsolete - use MX)
	QTYPE_MF                     // a mail forwarder (Obsolete - use MX)
	QTYPE_CNAME                  // the canonical name for an alias
	QTYPE_SOA                    // marks the start of a zone of authority
	QTYPE_MB                     // a mailbox domain name (EXPERIMENTAL)
	QTYPE_MG                     // a mail group member (EXPERIMENTAL)
	QTYPE_MR                     // a mail rename domain name  (EXPERIMENTAL)
	QTYPE_NULL                   // a null RR (EXPERIMENTAL)
	QTYPE_WKS                    // a well known service description
	QTYPE_PTR                    // a domain name pointer
	QTYPE_HINFO                  // host information
	QTYPE_MINFO                  // mailbox or mail list information
	QTYPE_MX                     // mail exchange
	QTYPE_TXT                    // text strings
)
const (
	QTYPE_AXFR     = iota + 252 // a request for a transfer of an entire zone
	QTYPE_MAILB                 // a request for mailbox-related records (MB, MG, or MR)
	QTYPE_MAILA                 // a request for mail agent RRs (Obsolete - see MX)
	QTYPE_ASTERISK              // a request for all records (symbol "*" in RFC)
)

const (
	QCLASS_IN       QClass = iota + 1 // the Internet
	QCLASS_CS                         // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
	QCLASS_CH                         // the CHAOS class
	QCLASS_HS                         // Hesiod [Dyer 87]
	QCLASS_ASTERISK = 255             // any class (symbol "*" in RFC)
)

func (qt QType) toString() string {
	switch qt {
	case QTYPE_A:
		return "A"
	case QTYPE_NS:
		return "NS"
	case QTYPE_MD:
		return "MD"
	case QTYPE_MF:
		return "MF"
	case QTYPE_CNAME:
		return "CNAME"
	case QTYPE_SOA:
		return "SOA"
	case QTYPE_MB:
		return "MB"
	case QTYPE_MG:
		return "MG"
	case QTYPE_MR:
		return "MR"
	case QTYPE_NULL:
		return "NULL"
	case QTYPE_WKS:
		return "WKS"
	case QTYPE_PTR:
		return "PTR"
	case QTYPE_HINFO:
		return "HINFO"
	case QTYPE_MINFO:
		return "MINFO"
	case QTYPE_MX:
		return "MX"
	case QTYPE_TXT:
		return "TXT"
	case QTYPE_AXFR:
		return "AXFR"
	case QTYPE_MAILB:
		return "MAILB"
	case QTYPE_MAILA:
		return "MAILA"
	case QTYPE_ASTERISK:
		return "*"
	default:
		panic("Unknown QType.")
	}
}

func (qc QClass) toString() string {
	switch qc {
	case QCLASS_IN:
		return "IN"
	case QCLASS_CS:
		return "CS"
	case QCLASS_CH:
		return "CH"
	case QCLASS_HS:
		return "HS"
	case QCLASS_ASTERISK:
		return "ASTERISK"
	default:
		panic("Unknown QCLASS.")
	}
}
