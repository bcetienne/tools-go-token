package validation

import (
	"regexp"
	"slices"
)

// PasswordValidation maintains password validation configuration and compiled
// regular expressions for efficient pattern matching operations.
type PasswordValidation struct {
	minLength         int
	unauthorizedWords []string
	lowercaseRegex    *regexp.Regexp
	uppercaseRegex    *regexp.Regexp
	digitRegex        *regexp.Regexp
	specialCharRegex  *regexp.Regexp
}

// PasswordValidationInterface defines the complete validation contract,
// enabling dependency injection and testing scenarios.
type PasswordValidationInterface interface {
	SetMinLength(minLength int)
	SetUnauthorizedWords(unauthorizedWords []string)
	PasswordContainsLowercase(password string) bool
	PasswordContainsUppercase(password string) bool
	PasswordContainsDigit(password string) bool
	PasswordContainsSpecialChar(password string) bool
	PasswordHasMinLength(password string) bool
	PasswordContainsUnauthorizedWord(password string) bool
	IsPasswordStrengthEnough(password string) bool
}

// NewPasswordValidation creates a new password validator with secure defaults.
// The validator is initialized with a minimum length of 8 characters,
// an empty unauthorized words list, and pre-compiled regex patterns
// for optimal performance.
func NewPasswordValidation() *PasswordValidation {
	passwordValidation := &PasswordValidation{
		minLength:         8,
		unauthorizedWords: []string{},
		lowercaseRegex:    regexp.MustCompile(`[a-z]`),
		uppercaseRegex:    regexp.MustCompile(`[A-Z]`),
		digitRegex:        regexp.MustCompile(`\d`),
		specialCharRegex:  regexp.MustCompile(`[!@#$%^&*()\-+={}[\]|\\:;"'<>,.?/~` + "`" + `_]`),
	}
	return passwordValidation
}

// SetMinLength configures the minimum acceptable password length.
// Values below 8 characters are silently rejected to maintain
// baseline security standards.
func (pv *PasswordValidation) SetMinLength(minLength int) {
	// Avoid skip the minimum security requirements
	if minLength < 8 {
		return
	}
	pv.minLength = minLength
}

// SetUnauthorizedWords defines a blacklist of prohibited passwords.
// Validation performs exact string matching and is case-sensitive.
func (pv *PasswordValidation) SetUnauthorizedWords(unauthorizedWords []string) {
	pv.unauthorizedWords = unauthorizedWords
}

// PasswordContainsLowercase verifies the presence of lowercase letters (a-z)
// in the provided password string.
func (pv *PasswordValidation) PasswordContainsLowercase(password string) bool {
	return pv.lowercaseRegex.MatchString(password)
}

// PasswordContainsUppercase verifies the presence of uppercase letters (A-Z)
// in the provided password string.
func (pv *PasswordValidation) PasswordContainsUppercase(password string) bool {
	return pv.uppercaseRegex.MatchString(password)
}

// PasswordContainsDigit verifies the presence of numeric digits (0-9)
// in the provided password string.
func (pv *PasswordValidation) PasswordContainsDigit(password string) bool {
	return pv.digitRegex.MatchString(password)
}

// PasswordContainsSpecialChar verifies the presence of special characters
// in the provided password string. Accepted characters include:
// !@#$%^&*()-+={}[]|\:;"'<>,.?/~_
func (pv *PasswordValidation) PasswordContainsSpecialChar(password string) bool {
	return pv.specialCharRegex.MatchString(password)
}

// PasswordHasMinLength validates that the password meets the configured
// minimum length requirement.
func (pv *PasswordValidation) PasswordHasMinLength(password string) bool {
	return len(password) >= pv.minLength
}

// PasswordContainsUnauthorizedWord checks if the password exactly matches
// any blacklisted word in the unauthorized words list.
// Returns true if the password is found in the blacklist.
func (pv *PasswordValidation) PasswordContainsUnauthorizedWord(password string) bool {
	if len(pv.unauthorizedWords) == 0 {
		return false
	}
	return slices.Contains(pv.unauthorizedWords, password)
}

// IsPasswordStrengthEnough performs comprehensive validation against all
// configured rules. The password must satisfy ALL requirements:
//   - Contains lowercase letters
//   - Contains uppercase letters
//   - Contains digits
//   - Contains special characters
//   - Meets minimum length
//   - Not found in unauthorized words list
//
// Returns true if the password passes all validation rules.
func (pv *PasswordValidation) IsPasswordStrengthEnough(password string) bool {
	return pv.PasswordContainsLowercase(password) &&
		pv.PasswordContainsUppercase(password) &&
		pv.PasswordContainsDigit(password) &&
		pv.PasswordContainsSpecialChar(password) &&
		!pv.PasswordContainsUnauthorizedWord(password) &&
		pv.PasswordHasMinLength(password)
}
