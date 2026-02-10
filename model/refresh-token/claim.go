package refresh_token

import "github.com/golang-jwt/jwt/v5"

// Claim represents the JWT token claims structure.
// Extends jwt.RegisteredClaims with custom fields for token type and email.
//
// Custom fields:
//   - KeyType: Discriminator for token type ("access" vs other types)
//   - Email: User's email address for quick access
//
// Standard JWT claims (inherited from jwt.RegisteredClaims):
//   - Subject: User's unique identifier (UUID or numeric ID as string) - RFC 7519 compliant
//   - ExpiresAt: Token expiration timestamp
//   - IssuedAt: Token creation timestamp
//   - NotBefore: Token valid-from timestamp
//   - Issuer: Application identifier
//   - ID (jti): Unique token identifier (UUID)
//
// JSON serialization:
//   - Tags enable JWT marshaling/unmarshaling
//   - Example: {"key_type": "access", "email": "user@example.com", "sub": "550e8400-...", "exp": 1234567890, ...}
type Claim struct {
	KeyType string `json:"key_type"`
	Email   string `json:"email"`
	jwt.RegisteredClaims
}
