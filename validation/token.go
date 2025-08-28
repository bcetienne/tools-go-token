package validation

import "errors"

func IsIncomingTokenValid(token string, tokenMaxLength int) error {
	if len(token) == 0 {
		return errors.New("empty token")
	}
	if len(token) > tokenMaxLength {
		return errors.New("token too long")
	}
	return nil
}
