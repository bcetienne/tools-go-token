package model

import "time"

type Token struct {
	TokenID    int       `json:"token_id"`
	UserID     int       `json:"user_id"`
	TokenValue string    `json:"token_value"`
	TokenType  string    `json:"token_type"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
}

func NewToken(userID int, token, tokenType string, expiresAt time.Time) *Token {
	return &Token{
		UserID:     userID,
		TokenValue: token,
		TokenType:  tokenType,
		ExpiresAt:  expiresAt,
	}
}
