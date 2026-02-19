package auth

// User represents an authenticated user with core identity fields.
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
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// UserInterface defines the methods for accessing user identity fields.
type UserInterface interface {
	GetID() string
	GetEmail() string
}

// NewUser creates a new User instance with the provided identity fields.
//
// Parameters:
//   - id: User identifier as string (UUID, numeric ID, or any unique identifier)
//   - email: User's email address
//
// Returns:
//   - *User: Initialized user ready for token generation
//
// Example:
//
//	// With UUID
//	user := modelAuth.NewUser("550e8400-e29b-41d4-a716-446655440000", "user@example.com")
//	// With numeric ID
//	user := modelAuth.NewUser("123", "user@example.com")
//	accessToken, err := accessService.CreateAccessToken(user)
func NewUser(id, email string) *User {
	return &User{
		ID:    id,
		Email: email,
	}
}

// GetID returns the user's unique identifier.
// Used as the JWT Subject claim in access tokens.
func (au *User) GetID() string {
	return au.ID
}

// GetEmail returns the user's email address.
// Used as a custom claim in JWT tokens.
func (au *User) GetEmail() string {
	return au.Email
}
