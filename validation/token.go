package validation

import "errors"

// IsIncomingTokenValid validates the format of an incoming token string.
// Performs basic validation checks for token length and emptiness.
//
// Validations:
//   - Non-empty: Token must contain at least one character
//   - Length check: Token must not exceed tokenMaxLength
//
// This is a generic validation function used by multiple services:
//   - RefreshTokenService: tokenMaxLength = 255
//   - PasswordResetService: tokenMaxLength = 32
//
// Parameters:
//   - token: The token string to validate
//   - tokenMaxLength: Maximum allowed length for the token
//
// Returns:
//   - error: Validation error with descriptive message, nil if valid
//
// Example:
//
//	if err := validation.IsIncomingTokenValid(token, 255); err != nil {
//	    return fmt.Errorf("invalid token format: %w", err)
//	}
func IsIncomingTokenValid(token string, tokenMaxLength int) error {
	if len(token) == 0 {
		return errors.New("empty token")
	}
	if len(token) > tokenMaxLength {
		return errors.New("token too long")
	}
	return nil
}
