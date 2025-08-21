package refresh_token

import "github.com/golang-jwt/jwt/v5"

type Claim struct {
	KeyType string `json:"key_type"`
	UserID  int    `json:"user_id"`
	jwt.RegisteredClaims
}
