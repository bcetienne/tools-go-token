package service

import (
	"errors"
	"fmt"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	modelRefreshToken "github.com/bcetienne/tools-go-token/model/refresh-token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type AccessTokenService struct {
	config *lib.Config
}

type AccessTokenServiceInterface interface {
	CreateAccessToken(user *modelRefreshToken.AuthUser) (string, error)
	VerifyAccessToken(token string) (*modelRefreshToken.Claim, error)
}

func NewAccessTokenService(config *lib.Config) *AccessTokenService {
	return &AccessTokenService{
		config: config,
	}
}

func (at *AccessTokenService) CreateAccessToken(user *modelRefreshToken.AuthUser) (string, error) {
	duration, err := time.ParseDuration(at.config.JWTExpiry)
	if err != nil {
		return "", err
	}

	claim := modelRefreshToken.Claim{
		KeyType: "access",
		UserID:  user.UserID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    at.config.Issuer,
			Subject:   user.Email,
			ID:        uuid.New().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claim)
	return token.SignedString([]byte(at.config.JWTSecret))
}

func (at *AccessTokenService) VerifyAccessToken(token string) (*modelRefreshToken.Claim, error) {
	t, err := jwt.ParseWithClaims(token, &modelRefreshToken.Claim{}, func(token *jwt.Token) (any, error) {
		return []byte(at.config.JWTSecret), nil
	}, jwt.WithLeeway(5*time.Second))

	if err != nil {
		// Specific case if the token is expired (to check if refresh is possible)
		if errors.Is(err, jwt.ErrTokenExpired) {
			return t.Claims.(*modelRefreshToken.Claim), jwt.ErrTokenExpired
		}
		return nil, err
	}

	if claim, ok := t.Claims.(*modelRefreshToken.Claim); ok && t.Valid {
		return claim, nil
	}

	return nil, fmt.Errorf("invalid token claim")
}
