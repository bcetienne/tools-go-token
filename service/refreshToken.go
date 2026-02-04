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
	refreshTokenMaxLength      int    = 255
	redisStoreNameRefreshToken string = "refresh"
)

type RefreshTokenService struct {
	db     *redis.Client
	config *lib.Config
}

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
