package refresh_token

import "github.com/golang-jwt/jwt/v5"

// Claim represents the JWT token claims structure.
// Extends jwt.RegisteredClaims with custom fields for token type and user ID.
//
// Custom fields:
//   - KeyType: Discriminator for token type ("access" vs other types)
//   - UserID: Numeric user identifier for quick user lookup
//
// Standard JWT claims (inherited from jwt.RegisteredClaims):
//   - ExpiresAt: Token expiration timestamp
//   - IssuedAt: Token creation timestamp
//   - NotBefore: Token valid-from timestamp
//   - Issuer: Application identifier
//   - Subject: User's email address
//   - ID (jti): Unique token identifier (UUID)
//
// JSON serialization:
//   - Tags enable JWT marshaling/unmarshaling
//   - Example: {"key_type": "access", "user_id": 123, "exp": 1234567890, ...}
type Claim struct {
	KeyType string `json:"key_type"`
	UserID  int    `json:"user_id"`
	jwt.RegisteredClaims
}
