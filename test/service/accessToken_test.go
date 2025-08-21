package service

import (
	"errors"

	libRefreshToken "github.com/bcetienne/tools-go-token/lib/refresh-token"
	modelRefreshToken "github.com/bcetienne/tools-go-token/model/refresh-token"

	"log"
	"testing"
	"time"

	"github.com/bcetienne/tools-go-token/service"
	"github.com/golang-jwt/jwt/v5"
)

func Test_Auth_AccessToken_CreateAccessToken_TableDriven(t *testing.T) {
	tests := []struct {
		testName      string
		expectSuccess bool
		jwtExpiry     string
	}{
		{
			testName:      "Success",
			expectSuccess: true,
			jwtExpiry:     "12h",
		},
		{
			testName:      "Fail - No duration",
			expectSuccess: false,
			jwtExpiry:     "",
		},
		{
			testName:      "Fail - Negative duration",
			expectSuccess: false,
			jwtExpiry:     "-12h",
		},
	}

	user := modelRefreshToken.AuthUser{
		UserID:   1,
		UserUUID: "123-123-123",
		Email:    "user@mail.com",
	}
	config := libRefreshToken.Config{
		Issuer:             "test_auth.com",
		JWTSecret:          "rand0mString_",
		RefreshTokenExpiry: "12h",
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			config.JWTExpiry = tt.jwtExpiry
			accessTokenService := service.NewAccessTokenService(&config)
			at, err := accessTokenService.CreateAccessToken(&user)
			if err != nil {
				if tt.expectSuccess {
					t.Fatalf("The test expect no error, got : %v", err)
				}
			}
			if len(at) != 312 && tt.expectSuccess {
				t.Fatalf("The token should have a length of 312, got %d", len(at))
			}
		})
	}
}

func Test_Auth_AccessToken_VerifyAccessToken_TableDriven(t *testing.T) {
	tests := []struct {
		testName      string
		token         string
		expectSuccess bool
	}{
		{
			testName:      "Success",
			token:         "",
			expectSuccess: true,
		},
		{
			testName:      "Fail - Bad token",
			token:         "bad_token",
			expectSuccess: false,
		},
	}

	user := modelRefreshToken.AuthUser{
		UserID:   2,
		UserUUID: "456-456-456",
		Email:    "miss@mail.com",
	}
	config := libRefreshToken.Config{
		Issuer:             "test_auth.com",
		JWTSecret:          "secureStr1ng_",
		JWTExpiry:          "12h",
		RefreshTokenExpiry: "3h",
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			accessTokenService := service.NewAccessTokenService(&config)
			token, err := accessTokenService.CreateAccessToken(&user)
			if err != nil {
				t.Fatalf("The test expect no error on access token creation, got : %v", err)
			}
			if len(tt.token) == 0 {
				tt.token = token
			}

			verified, err := accessTokenService.VerifyAccessToken(token)

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("The test expect no error, got : %v", err)
				}
				if verified.UserID != user.UserID {
					t.Fatalf("Ther user ID does not match. Expected %d, got %d", user.UserID, verified.UserID)
				}
				if verified.Issuer != config.Issuer {
					if verified.Subject != user.Email {
						t.Fatalf("The subject does not match. Expected %s, got %s", user.Email, verified.Subject)
					}
					t.Fatalf("The issuer does not match. Expected %s, got %s", config.Issuer, verified.Issuer)
				}
			}
		})
	}
}

func Test_Auth_AccessToken_VerifyAccessToken_Expired(t *testing.T) {
	// This should be a "Success" either with an "error" because, the claim should not be NIL.
	// But it should be with a specific error when the token is expired.
	t.Run("Success - Expired token", func(t *testing.T) {
		user := modelRefreshToken.AuthUser{
			UserID:   3,
			UserUUID: "789-789-789",
			Email:    "mister@mail.com",
		}
		config := libRefreshToken.Config{
			Issuer:             "test_auth.com",
			JWTSecret:          "pass0rdHidden_",
			JWTExpiry:          "1s",
			RefreshTokenExpiry: "6h",
		}
		accessTokenService := service.NewAccessTokenService(&config)
		token, err := accessTokenService.CreateAccessToken(&user)
		if err != nil {
			t.Fatalf("The test expect no error on access token creation, got : %v", err)
		}

		// Do not go under 5 seconds. The leeway authorize an expired token for 5 seconds after the expiration time
		log.Printf("Sleeping test for 7 seconds...")
		time.Sleep(7 * time.Second)

		verified, err := accessTokenService.VerifyAccessToken(token)
		if err == nil {
			t.Fatal("The error should not be nil")
		}
		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Fatal("The error type should be a JWT Token Expired error")
		}
		if verified == nil {
			t.Fatal("The claim should not be NIL")
		}
	})
}

func Test_Auth_AccessToken_VerifyAccessToken_TwoDifferentTokens(t *testing.T) {
	t.Run("Success - Two different tokens", func(t *testing.T) {
		user := modelRefreshToken.AuthUser{
			UserID:   3,
			UserUUID: "789-789-789",
			Email:    "mister@mail.com",
		}
		secondUser := modelRefreshToken.AuthUser{
			UserID:   4,
			UserUUID: "000-000-000",
			Email:    "lady@mail.com",
		}
		config := libRefreshToken.Config{
			Issuer:             "test_auth.com",
			JWTSecret:          "super_Str0ngStr1ng_",
			JWTExpiry:          "4h",
			RefreshTokenExpiry: "2h",
		}
		accessTokenService := service.NewAccessTokenService(&config)
		token, err := accessTokenService.CreateAccessToken(&user)
		if err != nil {
			t.Fatalf("The test expect no error on access token creation, got : %v", err)
		}

		secondToken, err := accessTokenService.CreateAccessToken(&secondUser)
		if err != nil {
			t.Fatalf("The test expect no error on access token creation, got : %v", err)
		}

		if token == secondToken {
			t.Fatalf("Two users should not have the same token !")
		}
	})
}
