package refresh_token

type AuthUser struct {
	UserID   int    `json:"user_id"`
	UserUUID string `json:"user_uuid"`
	Email    string `json:"email"`
}

type AuthUserInterface interface {
	GetUserID() int
	GetEmail() string
	GetUserUUID() string
}

func NewAuthUser(userID int, uuid, email string) *AuthUser {
	return &AuthUser{
		UserID:   userID,
		UserUUID: uuid,
		Email:    email,
	}
}

func (au *AuthUser) GetEmail() string {
	return au.Email
}

func (au *AuthUser) GetUserUUID() string {
	return au.UserUUID
}

func (au *AuthUser) GetUserID() int {
	return au.UserID
}
