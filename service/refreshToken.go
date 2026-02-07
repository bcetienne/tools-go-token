package service

import (
	"context"
	"fmt"

	"errors"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/redis/go-redis/v9"

	"github.com/bcetienne/tools-go-token/validation"
)

const (
	// refreshTokenMaxLength defines the maximum character length for refresh tokens.
	// Tokens are 255-character cryptographically secure random strings.
	refreshTokenMaxLength int = 255

	// redisStoreNameRefreshToken is the Redis key prefix for refresh token storage.
	// Key pattern: "refresh:{userID}:{token}" with value "1" (existence check).
	// Multiple tokens per user are supported (multi-device sessions).
	redisStoreNameRefreshToken string = "refresh"
)

// RefreshTokenService manages long-lived refresh tokens with Redis persistence.
// Supports multiple active tokens per user for multi-device sessions.
//
// Key features:
//   - Multi-token support: Users can have multiple active tokens simultaneously
//   - Redis storage with automatic TTL expiration
//   - Cryptographically secure 255-character tokens
//   - User-scoped revocation (logout single device) and global revocation (logout all)
//
// Redis key pattern:
//   - Key: "refresh:{userID}:{token}"
//   - Value: "1" (existence indicates validity)
//   - TTL: Configured via RefreshTokenTTL (default: 1 hour)
//
// Multi-device support example:
//
//	User 123 logs in on phone → refresh:123:abc...
//	Same user logs in on laptop → refresh:123:def...
//	Both tokens remain valid until expiration or explicit revocation
type RefreshTokenService struct {
	db     *redis.Client
	config *lib.Config
}

// NewRefreshTokenService creates a new refresh token service instance with Redis persistence.
// Returns an error if the database client is nil or if RefreshTokenTTL is not configured.
//
// Parameters:
//   - ctx: Context for initialization (uses Background if nil)
//   - db: Redis client for token storage
//   - config: Configuration containing RefreshTokenTTL
//
// Returns:
//   - *RefreshTokenService: Initialized service ready for use
//   - error: Configuration or database validation errors
//
// Example:
//
//	refreshService, err := service.NewRefreshTokenService(ctx, redisClient, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewRefreshTokenService(ctx context.Context, db *redis.Client, config *lib.Config) (*RefreshTokenService, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if config.RefreshTokenTTL == nil {
		return nil, errors.New("refresh token ttl is nil") // Should no go further
	}

	if ctx == nil {
		ctx = context.Background()
	}

	service := &RefreshTokenService{db, config}

	return service, nil
}

// CreateRefreshToken generates a new refresh token for the specified user.
// Multiple tokens can exist per user (multi-device sessions).
// The token is a 255-character cryptographically secure random string.
//
// Token lifecycle:
//   - Created with configured TTL (default: 1 hour)
//   - Automatically expires via Redis TTL
//   - Does not invalidate existing tokens for the same user
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//
// Returns:
//   - *string: Pointer to the generated refresh token (255 characters)
//   - error: Validation or storage errors
//
// Example:
//
//	token, err := refreshService.CreateRefreshToken(ctx, 123)
//	if err != nil {
//	    return err
//	}
//	// Send token to client (store securely, httpOnly cookie recommended)
//	setRefreshTokenCookie(w, *token)
func (rts *RefreshTokenService) CreateRefreshToken(ctx context.Context, userID int) (*string, error) {
	if userID <= 0 {
		return nil, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Parse duration from configuration
	duration, err := time.ParseDuration(*rts.config.RefreshTokenTTL)
	if err != nil {
		return nil, err
	}

	// Create a random token
	token, err := lib.GenerateRandomString(refreshTokenMaxLength)
	if err != nil {
		return nil, err
	}

	// Add the token to Redis
	if err := rts.db.Set(ctx, fmt.Sprintf("%s:%d:%s", redisStoreNameRefreshToken, userID, token), "1", duration).Err(); err != nil {
		return nil, err
	}

	return &token, nil
}

// VerifyRefreshToken checks if the provided refresh token is valid for the user.
// Validates token format and checks existence in Redis.
//
// Verification process:
//  1. Validate userID > 0
//  2. Validate token format (length, non-empty)
//  3. Check Redis key "refresh:{userID}:{token}" exists
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//   - token: The refresh token to verify (255 characters)
//
// Returns:
//   - bool: true if token is valid and not expired, false otherwise
//   - error: Validation errors or Redis connection errors
//
// Example:
//
//	valid, err := refreshService.VerifyRefreshToken(ctx, 123, tokenString)
//	if err != nil {
//	    return err
//	}
//	if !valid {
//	    return errors.New("invalid or expired refresh token")
//	}
//	// Token valid - generate new access token
func (rts *RefreshTokenService) VerifyRefreshToken(ctx context.Context, userID int, token string) (bool, error) {
	if userID <= 0 {
		return false, errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, refreshTokenMaxLength); err != nil {
		return false, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	val, err := rts.db.Get(ctx, fmt.Sprintf("%s:%d:%s", redisStoreNameRefreshToken, userID, token)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil // Token doesn't exist or expired - not an error
	}
	if err != nil {
		return false, err // Real Redis error
	}
	return val == "1", nil
}

// RevokeRefreshToken immediately invalidates a specific refresh token.
// Other tokens for the same user remain valid (single-device logout).
//
// Use cases:
//   - User logs out from one device (other devices remain logged in)
//   - Security measure after suspicious activity on specific device
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - token: The refresh token to revoke (255 characters)
//   - userID: User identifier (must be > 0)
//
// Returns:
//   - error: Validation or storage errors
//
// Example:
//
//	// User clicks "Logout" button
//	err := refreshService.RevokeRefreshToken(ctx, tokenFromCookie, 123)
//	if err != nil {
//	    log.Printf("Failed to revoke token: %v", err)
//	}
//	// Clear client-side cookie
func (rts *RefreshTokenService) RevokeRefreshToken(ctx context.Context, token string, userID int) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, refreshTokenMaxLength); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	return rts.db.Del(ctx, fmt.Sprintf("%s:%d:%s", redisStoreNameRefreshToken, userID, token)).Err()
}

// RevokeAllUserRefreshTokens invalidates all refresh tokens for a specific user.
// Logs out the user from all devices simultaneously.
//
// Use cases:
//   - User clicks "Logout from all devices" in account settings
//   - Password change (force re-login everywhere)
//   - Security breach detected for specific user
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier (must be > 0)
//
// Returns:
//   - error: Storage errors encountered during revocation
//
// Example:
//
//	// User changes password - force logout everywhere
//	err := refreshService.RevokeAllUserRefreshTokens(ctx, 123)
//	if err != nil {
//	    return fmt.Errorf("failed to revoke user sessions: %w", err)
//	}
func (rts *RefreshTokenService) RevokeAllUserRefreshTokens(ctx context.Context, userID int) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	keys := rts.db.Scan(ctx, 0, fmt.Sprintf("%s:%d:*", redisStoreNameRefreshToken, userID), 0).Iterator()
	for keys.Next(ctx) {
		key := keys.Val()
		if err := rts.db.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete key %s : %w", key, err)
		}
	}

	return keys.Err()
}

// RevokeAllRefreshTokens revokes all refresh tokens for all users.
// Used for emergency security measures or system maintenance.
//
// Warning: This is a destructive operation that logs out all users.
//
// Use cases:
//   - Security breach (invalidate all sessions immediately)
//   - System maintenance (force all users to re-authenticate)
//   - Test cleanup
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//
// Returns:
//   - error: Storage errors encountered during revocation
//
// Example:
//
//	// Emergency: security breach detected
//	err := refreshService.RevokeAllRefreshTokens(ctx)
//	if err != nil {
//	    log.Fatal("Failed to revoke all tokens: %v", err)
//	}
//	log.Println("All users logged out - system secure")
func (rts *RefreshTokenService) RevokeAllRefreshTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	keys := rts.db.Scan(ctx, 0, fmt.Sprintf("%s:*", redisStoreNameRefreshToken), 0).Iterator()
	for keys.Next(ctx) {
		key := keys.Val()
		if err := rts.db.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete key %s : %w", key, err)
		}
	}

	return keys.Err()
}
