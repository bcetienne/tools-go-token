package lib

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GenerateRandomString creates a cryptographically secure random string
// of the specified length using alphanumeric characters and hyphens.
// The function uses crypto/rand for secure random number generation,
// making it suitable for authentication tokens, session identifiers,
// and other security-sensitive applications.
//
// The character set includes:
//   - Digits: 0-9
//   - Uppercase letters: A-Z
//   - Lowercase letters: a-z
//   - Hyphen: -
//
// Parameters:
//   - n: The desired length of the generated string
//
// Returns:
//   - string: A randomly generated string of length n
//   - error: An error if random number generation fails
//
// Example:
//
//	token, err := GenerateRandomString(32)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// token contains a 32-character random string
func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

// GenerateOTP creates a random 6 digits code (One Time Password) from 000000 to 999999
func GenerateOTP() (string, error) {
	otp, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", otp.Int64()), nil
}
