package validation

import "regexp"

// Pre-compiled regex at package level for performance
var otpDigitRegex = regexp.MustCompile(`^\d{6}$`)

// OTPValidation provides validation methods for OTP codes.
// Ensures OTP codes are exactly 6 numeric digits.
type OTPValidation struct {
	length     int
	digitRegex *regexp.Regexp
}

// OTPValidationInterface defines the methods for OTP validation.
type OTPValidationInterface interface {
	OTPHasLength(otp string) bool
	OTPOnlyContainsDigits(otp string) bool
	ISOTPValid(otp string) bool
}

// NewOTPValidation creates a new OTP validator instance.
// The validator ensures OTP codes are exactly 6 numeric digits.
//
// Returns:
//   - *OTPValidation: Validator ready for use
//
// Example:
//
//	validator := validation.NewOTPValidation()
//	if validator.ISOTPValid("123456") {
//	    log.Println("Valid OTP")
//	}
func NewOTPValidation() *OTPValidation {
	return &OTPValidation{
		length:     6,
		digitRegex: otpDigitRegex,
	}
}

// OTPHasLength checks if the OTP is exactly 6 characters long.
//
// Parameters:
//   - otp: The OTP code to validate
//
// Returns:
//   - bool: true if length is exactly 6, false otherwise
func (ov *OTPValidation) OTPHasLength(otp string) bool {
	return len(otp) == ov.length
}

// OTPOnlyContainsDigits checks if the OTP contains only numeric digits.
// Validates using a pre-compiled regex pattern (^\d{6}$).
//
// Parameters:
//   - otp: The OTP code to validate
//
// Returns:
//   - bool: true if OTP is 6 numeric digits, false otherwise
func (ov *OTPValidation) OTPOnlyContainsDigits(otp string) bool {
	return ov.digitRegex.MatchString(otp)
}

// ISOTPValid performs complete OTP validation.
// Checks both length (6 characters) and format (numeric only).
//
// Valid examples: "123456", "000042", "999999"
// Invalid examples: "12345", "1234567", "12345a", "abc123"
//
// Parameters:
//   - otp: The OTP code to validate
//
// Returns:
//   - bool: true if OTP is valid (6 numeric digits), false otherwise
//
// Example:
//
//	validator := validation.NewOTPValidation()
//	if validator.ISOTPValid("123456") {
//	    // OTP format is valid, proceed with verification
//	}
func (ov *OTPValidation) ISOTPValid(otp string) bool {
	return ov.OTPHasLength(otp) &&
		ov.OTPOnlyContainsDigits(otp)
}
