package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bcetienne/tools-go-token/v4/lib"
	"github.com/bcetienne/tools-go-token/v4/validation"
	"github.com/redis/go-redis/v9"
)

const (
	// passwordResetTokenMaxLength defines the maximum character length for password reset tokens.
	// Tokens are 32-character cryptographically secure random strings.
	passwordResetTokenMaxLength int = 32

	// redisStoreNamePasswordReset is the Redis key prefix for password reset token storage.
	// Key pattern: "password_reset:{userID}" with token value stored directly.
	// Single-token pattern: creating a new token invalidates the previous one.
	redisStoreNamePasswordReset string = "password_reset"
)

// PasswordResetService manages temporary password reset tokens with Redis persistence.
// Enforces single active token per user (security measure).
//
// Key features:
//   - Single-token enforcement: Creating new token invalidates previous one
//   - Short TTL: Default 10 minutes (configurable via PasswordResetTTL)
//   - Cryptographically secure 32-character tokens
//   - Revocation requires token match (prevents unauthorized revocation)
//   - Automatic expiration via Redis TTL
//
// Redis key pattern:
//   - Key: "password_reset:{userID}"
//   - Value: The actual token string (compared during verification)
//   - TTL: Configured via PasswordResetTTL (default: 10 minutes)
//
// Security rationale:
//   - Single-token prevents multiple concurrent reset attempts
//   - Short TTL limits exposure window for stolen tokens
//   - Token match on revocation prevents malicious invalidation
type PasswordResetService struct {
	db     *redis.Client
	config *lib.Config
}

// NewPasswordResetService creates a new password reset service instance with Redis persistence.
// Returns an error if the database client is nil or if PasswordResetTTL is not configured.
//
// Parameters:
//   - ctx: Context for initialization (uses Background if nil)
//   - db: Redis client for token storage
//   - config: Configuration containing PasswordResetTTL
//
// Returns:
//   - *PasswordResetService: Initialized service ready for use
//   - error: Configuration or database validation errors
//
// Example:
//
//	resetService, err := service.NewPasswordResetService(ctx, redisClient, config)
//	if err != nil {
//	    log.Fatal(err)
//	}
func NewPasswordResetService(ctx context.Context, db *redis.Client, config *lib.Config) (*PasswordResetService, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if config.PasswordResetTTL == nil {
		return nil, errors.New("password reset ttl is nil") // Should no go further
	}

	if ctx == nil {
		ctx = context.Background()
	}

	service := &PasswordResetService{db, config}

	return service, nil
}

// CreatePasswordResetToken generates a new password reset token for the specified user.
// Creating a new token automatically invalidates any previous token for the user.
// The token is a 32-character cryptographically secure random string.
//
// Token lifecycle:
//   - Created with short TTL (default: 10 minutes)
//   - Automatically expires via Redis TTL
//   - Replaces any existing reset token for the user (single-token enforcement)
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier as string (UUID, numeric ID, or any unique identifier)
//
// Returns:
//   - *string: Pointer to the generated reset token (32 characters)
//   - error: Validation or storage errors
//
// Example:
//
//	token, err := resetService.CreatePasswordResetToken(ctx, "550e8400-e29b-41d4-a716-446655440000")
//	if err != nil {
//	    return err
//	}
//	// Send token via email: "Reset link: /reset?token=abc123..."
//	sendResetEmail(userEmail, *token)
func (prs *PasswordResetService) CreatePasswordResetToken(ctx context.Context, userID string) (*string, error) {
	if userID == "" {
		return nil, errors.New("invalid user id")
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Parse duration from configuration
	duration, err := time.ParseDuration(*prs.config.PasswordResetTTL)
	if err != nil {
		return nil, err
	}

	// Create a random token
	token, err := lib.GenerateRandomString(passwordResetTokenMaxLength)
	if err != nil {
		return nil, err
	}

	// Add the token to Redis
	if err := prs.db.Set(ctx, fmt.Sprintf("%s:%s", redisStoreNamePasswordReset, userID), token, duration).Err(); err != nil {
		return nil, err
	}

	return &token, nil
}

// VerifyPasswordResetToken checks if the provided reset token is valid for the user.
// Validates token format and compares with stored token value in Redis.
//
// Verification process:
//  1. Validate userID is not empty
//  2. Validate token format (length, non-empty)
//  3. Retrieve stored token from Redis
//  4. Compare provided token with stored token (exact match)
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier as string (UUID, numeric ID, or any unique identifier)
//   - token: The reset token to verify (32 characters)
//
// Returns:
//   - bool: true if token is valid and matches stored token, false otherwise
//   - error: Validation errors or Redis connection errors
//
// Example:
//
//	valid, err := resetService.VerifyPasswordResetToken(ctx, "550e8400-e29b-41d4-a716-446655440000", tokenFromURL)
//	if err != nil {
//	    return err
//	}
//	if !valid {
//	    return errors.New("invalid or expired reset token")
//	}
//	// Token valid - allow user to set new password
func (prs *PasswordResetService) VerifyPasswordResetToken(ctx context.Context, userID string, token string) (bool, error) {
	if userID == "" {
		return false, errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return false, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	val, err := prs.db.Get(ctx, fmt.Sprintf("%s:%s", redisStoreNamePasswordReset, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil // Token doesn't exist or expired - not an error
	}
	if err != nil {
		return false, err // Real Redis error
	}
	return val == token, nil
}

// RevokePasswordResetToken immediately invalidates a password reset token.
// Requires providing the correct token to prevent unauthorized revocation (security measure).
//
// Security feature:
//   - Token must match stored token before revocation
//   - Prevents attackers from invalidating legitimate reset attempts
//   - Returns error if token doesn't match or doesn't exist
//
// Use cases:
//   - User successfully resets password (token no longer needed)
//   - User requests cancellation of reset process
//
// Parameters:
//   - ctx: Context for the operation (uses Background if nil)
//   - userID: User identifier as string (UUID, numeric ID, or any unique identifier)
//   - token: The reset token to revoke (must match stored token)
//
// Returns:
//   - error: Validation errors, token mismatch, or storage errors
//
// Example:
//
//	// After successful password change
//	err := resetService.RevokePasswordResetToken(ctx, "550e8400-e29b-41d4-a716-446655440000", tokenFromURL)
//	if err != nil {
//	    log.Printf("Failed to revoke reset token: %v", err)
//	}
func (prs *PasswordResetService) RevokePasswordResetToken(ctx context.Context, userID string, token string) error {
	if userID == "" {
		return errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Get the stored token to verify it matches before revoking
	key := fmt.Sprintf("%s:%s", redisStoreNamePasswordReset, userID)
	storedToken, err := prs.db.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return errors.New("token not found or already revoked")
	}
	if err != nil {
		return err
	}

	// Verify the token matches
	if storedToken != token {
		return errors.New("token mismatch")
	}

	// Delete the token
	return prs.db.Del(ctx, key).Err()
}

// RevokeAllPasswordResetTokens revokes all password reset tokens for all users.
// Used for emergency security measures or testing cleanup.
//
// Warning: This is a destructive operation that invalidates all pending reset requests.
//
// Use cases:
//   - Security breach (invalidate all reset tokens immediately)
//   - System maintenance
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
//	err := resetService.RevokeAllPasswordResetTokens(ctx)
//	if err != nil {
//	    log.Fatal("Failed to revoke all reset tokens: %v", err)
//	}
//	log.Println("All password reset requests invalidated")
func (prs *PasswordResetService) RevokeAllPasswordResetTokens(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	keys := prs.db.Scan(ctx, 0, fmt.Sprintf("%s:*", redisStoreNamePasswordReset), 0).Iterator()
	for keys.Next(ctx) {
		key := keys.Val()
		if err := prs.db.Del(ctx, key).Err(); err != nil {
			return fmt.Errorf("failed to delete key %s : %w", key, err)
		}
	}

	return keys.Err()
}
