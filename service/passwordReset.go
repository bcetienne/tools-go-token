package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/validation"
	"github.com/redis/go-redis/v9"
)

const (
	passwordResetTokenMaxLength int    = 32
	redisStoreNamePasswordReset string = "password_reset"
)

type PasswordResetService struct {
	db     *redis.Client
	config *lib.Config
}

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

func (prs *PasswordResetService) CreatePasswordResetToken(ctx context.Context, userID int) (*string, error) {
	if userID <= 0 {
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
	if err := prs.db.Set(ctx, fmt.Sprintf("%s:%d", redisStoreNamePasswordReset, userID), token, duration).Err(); err != nil {
		return nil, err
	}

	return &token, nil
}

func (prs *PasswordResetService) VerifyPasswordResetToken(ctx context.Context, userID int, token string) (bool, error) {
	if userID <= 0 {
		return false, errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return false, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	val, err := prs.db.Get(ctx, fmt.Sprintf("%s:%d", redisStoreNamePasswordReset, userID)).Result()
	if errors.Is(err, redis.Nil) {
		return false, nil // Token doesn't exist or expired - not an error
	}
	if err != nil {
		return false, err // Real Redis error
	}
	return val == token, nil
}

func (prs *PasswordResetService) RevokePasswordResetToken(ctx context.Context, userID int, token string) error {
	if userID <= 0 {
		return errors.New("invalid user id")
	}

	if err := validation.IsIncomingTokenValid(token, passwordResetTokenMaxLength); err != nil {
		return err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	// Get the stored token to verify it matches before revoking
	key := fmt.Sprintf("%s:%d", redisStoreNamePasswordReset, userID)
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
