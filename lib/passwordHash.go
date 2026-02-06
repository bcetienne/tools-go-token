package lib

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHash provides secure password hashing and verification functionality
// using bcrypt algorithm with a configurable cost factor.
// Default cost is 14 for optimal security in production.
type PasswordHash struct {
	cost int
}

// PasswordHashInterface defines the contract for password hashing operations,
// enabling dependency injection and testing scenarios.
type PasswordHashInterface interface {
	Hash(password string) (string, error)
	CheckHash(password, hash string) bool
}

// NewPasswordHash creates a new password hasher instance with the default
// cost factor of 14. This provides strong protection against brute-force
// attacks while maintaining reasonable performance for authentication operations.
func NewPasswordHash() *PasswordHash {
	return &PasswordHash{cost: 14}
}

// NewPasswordHashWithCost creates a new password hasher instance with a custom
// cost factor. Use lower cost values (e.g., 4-6) for testing environments to
// improve test performance. Production environments should use the default cost
// of 14 via NewPasswordHash().
//
// Cost factor guidelines:
//   - 4-6: Fast, suitable for testing (completes in milliseconds)
//   - 10-12: Medium security, faster authentication
//   - 14+: High security, recommended for production (default)
func NewPasswordHashWithCost(cost int) *PasswordHash {
	return &PasswordHash{cost: cost}
}

// Hash generates a secure bcrypt hash of the provided password using
// the configured cost factor. Empty passwords are rejected to ensure security.
// Each call to Hash with the same password produces a different hash
// due to bcrypt's built-in salt generation.
//
// Returns an error if the password is empty or if bcrypt hash generation fails.
func (ph *PasswordHash) Hash(password string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("empty password")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), ph.cost)
	return string(bytes), err
}

// CheckHash verifies whether the provided password matches the given bcrypt hash.
// Both password and hash must be non-empty strings. The function safely handles
// invalid hashes and returns false for any verification failure.
//
// Returns true if the password matches the hash, false otherwise.
// Empty passwords or hashes always return false.
func (ph *PasswordHash) CheckHash(password, hash string) bool {
	if len(password) == 0 || len(hash) == 0 {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil // Return true when no errors
}
