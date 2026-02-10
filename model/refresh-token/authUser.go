package refresh_token

// AuthUser represents an authenticated user with core identity fields.
// Used as input for JWT access token generation and service operations.
//
// Fields:
//   - ID: Universal user identifier (UUID string or numeric ID as string)
//   - Email: User's email address
//
// JSON serialization:
//   - Tags enable JSON marshaling/unmarshaling
//   - Example: {"id": "550e8400-e29b-41d4-a716-446655440000", "email": "user@example.com"}
//   - Example: {"id": "123", "email": "user@example.com"}
type AuthUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// AuthUserInterface defines the methods for accessing user identity fields.
type AuthUserInterface interface {
	GetID() string
	GetEmail() string
}

// NewAuthUser creates a new AuthUser instance with the provided identity fields.
//
// Parameters:
//   - id: User identifier as string (UUID, numeric ID, or any unique identifier)
//   - email: User's email address
//
// Returns:
//   - *AuthUser: Initialized user ready for token generation
//
// Example:
//
//	// With UUID
//	user := modelRefreshToken.NewAuthUser("550e8400-e29b-41d4-a716-446655440000", "user@example.com")
//	// With numeric ID
//	user := modelRefreshToken.NewAuthUser("123", "user@example.com")
//	accessToken, err := accessService.CreateAccessToken(user)
func NewAuthUser(id, email string) *AuthUser {
	return &AuthUser{
		ID:    id,
		Email: email,
	}
}

// GetID returns the user's unique identifier.
// Used as the JWT Subject claim in access tokens.
func (au *AuthUser) GetID() string {
	return au.ID
}

// GetEmail returns the user's email address.
// Used as a custom claim in JWT tokens.
func (au *AuthUser) GetEmail() string {
	return au.Email
}
