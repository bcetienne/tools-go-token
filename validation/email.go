// Package validation provides input validation utilities for emails, passwords, tokens, and OTPs.
package validation

import "regexp"

// EmailValidation maintains a compiled regular expression for efficient
// email address pattern matching operations.
type EmailValidation struct {
	emailRegex *regexp.Regexp
}

// EmailValidationInterface defines the email validation contract,
// enabling dependency injection and testing scenarios.
type EmailValidationInterface interface {
	IsValidEmail(email string) bool
}

// NewEmailValidation creates a new email validator with a pre-compiled
// RFC-compliant regular expression pattern. The validator accepts standard
// email formats including alphanumeric characters, dots, underscores,
// percent signs, plus signs, and hyphens in the local part, and
// alphanumeric characters, dots, and hyphens in the domain part.
func NewEmailValidation() *EmailValidation {
	return &EmailValidation{
		emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
	}
}

// IsValidEmail validates whether the provided string conforms to
// standard email address format requirements. The validation ensures
// the presence of a local part, @ symbol, domain name, and top-level
// domain with at least 2 characters.
//
// Returns true if the email address is properly formatted.
func (ev *EmailValidation) IsValidEmail(email string) bool {
	return ev.emailRegex.MatchString(email)
}
