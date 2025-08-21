package lib

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// PasswordHash provides secure password hashing and verification functionality
// using bcrypt algorithm with a cost factor of 14 for optimal security.
type PasswordHash struct {
}

// PasswordHashInterface defines the contract for password hashing operations,
// enabling dependency injection and testing scenarios.
type PasswordHashInterface interface {
	Hash(password string) (string, error)
	CheckHash(password, hash string) bool
}

// NewPasswordHash creates a new password hasher instance.
// The hasher uses bcrypt with a cost factor of 14, providing strong
// protection against brute-force attacks while maintaining reasonable
// performance for authentication operations.
func NewPasswordHash() *PasswordHash {
	return &PasswordHash{}
}

// Hash generates a secure bcrypt hash of the provided password using
// a cost factor of 14. Empty passwords are rejected to ensure security.
// Each call to Hash with the same password produces a different hash
// due to bcrypt's built-in salt generation.
//
// Returns an error if the password is empty or if bcrypt hash generation fails.
func (ph *PasswordHash) Hash(password string) (string, error) {
	if len(password) == 0 {
		return "", fmt.Errorf("empty password")
	}
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
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
