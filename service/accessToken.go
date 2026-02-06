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

// AccessTokenService manages JWT access token creation and verification.
// Unlike other services, this operates in-memory without database persistence.
// Access tokens are stateless, short-lived credentials verified using the JWT secret.
//
// Architecture:
//   - Stateless: No Redis/database storage required
//   - Short-lived: Configured via JWTExpiry (typically 15 minutes)
//   - Signed with HS256: Uses JWTSecret for signing and verification
//   - Claims include: UserID, email (subject), issuer, expiration, UUID (jti)
type AccessTokenService struct {
	config *lib.Config
}

// AccessTokenServiceInterface defines the methods for JWT access token management.
type AccessTokenServiceInterface interface {
	CreateAccessToken(user *modelRefreshToken.AuthUser) (string, error)
	VerifyAccessToken(token string) (*modelRefreshToken.Claim, error)
}

// NewAccessTokenService creates a new access token service instance.
// No database connection required - access tokens are stateless JWT tokens.
//
// Parameters:
//   - config: Configuration containing Issuer, JWTSecret, and JWTExpiry
//
// Returns:
//   - *AccessTokenService: Service ready for token creation and verification
//
// Example:
//
//	config := lib.NewConfig("myapp", "secret", "15m", ...)
//	accessService := service.NewAccessTokenService(config)
//	token, err := accessService.CreateAccessToken(user)
func NewAccessTokenService(config *lib.Config) *AccessTokenService {
	return &AccessTokenService{
		config: config,
	}
}

// CreateAccessToken generates a new JWT access token for an authenticated user.
// The token is signed with HS256 and includes standard JWT claims plus custom UserID.
//
// Token structure:
//   - KeyType: "access" (distinguishes from other token types)
//   - UserID: User's numeric identifier
//   - Subject: User's email address
//   - Issuer: Configured application issuer
//   - ExpiresAt: Current time + configured JWTExpiry
//   - IssuedAt/NotBefore: Current time
//   - ID (jti): Random UUID for token uniqueness
//
// Parameters:
//   - user: Authenticated user containing UserID, Email, and UUID
//
// Returns:
//   - string: Signed JWT token (format: header.payload.signature)
//   - error: Token generation or signing errors
//
// Example:
//
//	user := modelRefreshToken.NewAuthUser(123, "uuid-here", "user@example.com")
//	token, err := accessService.CreateAccessToken(user)
//	if err != nil {
//	    return err
//	}
//	// Send token to client: {"access_token": "eyJhbGciOi..."}
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

// VerifyAccessToken validates and parses a JWT access token.
// Verification includes signature check, expiration, and claim structure validation.
//
// Verification process:
//  1. Parse JWT and verify HS256 signature using JWTSecret
//  2. Check expiration with 5-second leeway (clock skew tolerance)
//  3. Validate claim structure matches expected format
//  4. Return parsed claims if valid
//
// Special handling:
//   - If token is expired (jwt.ErrTokenExpired), claims are still returned
//     along with the error, allowing the caller to extract UserID for
//     refresh token verification
//
// Parameters:
//   - token: JWT access token string to verify
//
// Returns:
//   - *modelRefreshToken.Claim: Parsed token claims (nil if invalid)
//   - error: jwt.ErrTokenExpired if expired but structurally valid,
//     other errors for invalid signature, malformed token, etc.
//
// Example:
//
//	claim, err := accessService.VerifyAccessToken(tokenString)
//	if err != nil {
//	    if errors.Is(err, jwt.ErrTokenExpired) {
//	        // Token expired - user can refresh using refresh token
//	        return handleTokenRefresh(claim.UserID)
//	    }
//	    return errors.New("invalid token")
//	}
//	// Token valid - proceed with authenticated request
//	userID := claim.UserID
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
