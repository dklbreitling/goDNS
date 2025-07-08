package dns

import (
	"regexp"
	"strings"
)

// StringToLabels converts a domain name string to DNS labels
func StringToLabels(domain string) []Label {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	
	if domain == "" {
		return []Label{{Length: 0, Data: nil}}
	}
	
	parts := strings.Split(domain, ".")
	labels := make([]Label, len(parts)+1)
	
	for i, part := range parts {
		labels[i] = Label{
			Length: byte(len(part)),
			Data:   []byte(part),
		}
	}
	
	// Add null terminator
	labels[len(parts)] = Label{Length: 0, Data: nil}
	
	return labels
}

// LabelsToString converts DNS labels to a domain name string
func LabelsToString(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	
	var parts []string
	for _, label := range labels {
		if label.Length == 0 {
			break // Null terminator
		}
		parts = append(parts, string(label.Data))
	}
	
	return strings.Join(parts, ".")
}

// ValidateDomain validates a domain name according to RFC standards
func ValidateDomain(domain string) error {
	if len(domain) == 0 {
		return &DomainError{Domain: domain, Reason: "domain cannot be empty"}
	}
	
	if len(domain) > 253 {
		return &DomainError{Domain: domain, Reason: "domain too long (max 253 characters)"}
	}
	
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")
	
	// Check each label
	labels := strings.Split(domain, ".")
	if len(labels) < 1 {
		return &DomainError{Domain: domain, Reason: "domain must have at least one label"}
	}
	
	labelRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$`)
	
	for _, label := range labels {
		if len(label) == 0 {
			return &DomainError{Domain: domain, Reason: "empty label not allowed"}
		}
		if len(label) > 63 {
			return &DomainError{Domain: domain, Reason: "label too long (max 63 characters)"}
		}
		if !labelRegex.MatchString(label) {
			return &DomainError{Domain: domain, Reason: "invalid characters in label: " + label}
		}
	}
	
	return nil
}

// DomainError represents a domain validation error
type DomainError struct {
	Domain string
	Reason string
}

func (e *DomainError) Error() string {
	return "invalid domain '" + e.Domain + "': " + e.Reason
}
