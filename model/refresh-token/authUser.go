// Package refresh_token contains data models for refresh token and JWT operations.
package refresh_token

// AuthUser represents an authenticated user with core identity fields.
// Used as input for JWT access token generation and service operations.
//
// Fields:
//   - UserID: Numeric user identifier (primary key)
//   - UserUUID: Universal unique identifier for the user
//   - Email: User's email address (used as JWT subject)
//
// JSON serialization:
//   - Tags enable JSON marshaling/unmarshaling
//   - Example: {"user_id": 123, "user_uuid": "uuid", "email": "user@example.com"}
type AuthUser struct {
	UserID   int    `json:"user_id"`
	UserUUID string `json:"user_uuid"`
	Email    string `json:"email"`
}

// AuthUserInterface defines the methods for accessing user identity fields.
type AuthUserInterface interface {
	GetUserID() int
	GetEmail() string
	GetUserUUID() string
}

// NewAuthUser creates a new AuthUser instance with the provided identity fields.
//
// Parameters:
//   - userID: Numeric user identifier (typically from database primary key)
//   - uuid: Universal unique identifier (typically UUID v4)
//   - email: User's email address
//
// Returns:
//   - *AuthUser: Initialized user ready for token generation
//
// Example:
//
//	user := modelRefreshToken.NewAuthUser(123, "550e8400-e29b-41d4-a716-446655440000", "user@example.com")
//	accessToken, err := accessService.CreateAccessToken(user)
func NewAuthUser(userID int, uuid, email string) *AuthUser {
	return &AuthUser{
		UserID:   userID,
		UserUUID: uuid,
		Email:    email,
	}
}

// GetEmail returns the user's email address.
// Used as the JWT subject claim in access tokens.
func (au *AuthUser) GetEmail() string {
	return au.Email
}

// GetUserUUID returns the user's universal unique identifier.
func (au *AuthUser) GetUserUUID() string {
	return au.UserUUID
}

// GetUserID returns the user's numeric identifier.
// Used as a custom claim in JWT tokens for quick user lookup.
func (au *AuthUser) GetUserID() int {
	return au.UserID
}
