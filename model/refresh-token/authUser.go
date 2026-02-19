package refresh_token

import "github.com/bcetienne/tools-go-token/v4/model/auth"

// Deprecated: Use github.com/bcetienne/tools-go-token/v4/model/auth instead.
// Will be removed in v5.0.0.
type AuthUser = auth.User

// Deprecated: Use github.com/bcetienne/tools-go-token/v4/model/auth instead.
// Will be removed in v5.0.0.
type AuthUserInterface = auth.UserInterface

// Deprecated: Use github.com/bcetienne/tools-go-token/v4/model/auth instead.
// Will be removed in v5.0.0.
func NewAuthUser(id, email string) *AuthUser {
	return auth.NewUser(id, email)
}
