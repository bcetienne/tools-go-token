package service

import (
	"context"
	"testing"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/service"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupService(t *testing.T) *service.RefreshTokenService {
	rts, err := service.NewRefreshTokenService(t.Context(), redisDB, config)
	require.NoError(t, err)

	// Clear all tokens to ensure clean state
	err = rts.RevokeAllRefreshTokens(t.Context())
	require.NoError(t, err)

	return rts
}

func TestNewRefreshTokenService(t *testing.T) {
	t.Run("Should create service successfully", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(t.Context(), redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(context.TODO(), redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should fail with nil database", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(context.Background(), nil, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db is nil")
	})

	t.Run("Should fail with nil refresh token ttl", func(t *testing.T) {
		invalidConfig := &lib.Config{RefreshTokenTTL: nil}
		_, err := service.NewRefreshTokenService(context.Background(), redisDB, invalidConfig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refresh token ttl is nil")
	})
}

func TestCreateRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should create token successfully", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, *token)
		assert.Equal(t, 255, len(*token))
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := rts.CreateRefreshToken(context.Background(), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = rts.CreateRefreshToken(context.Background(), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		token, err := rts.CreateRefreshToken(context.TODO(), 123)
		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, *token)
	})

	t.Run("Should create different tokens for same user", func(t *testing.T) {
		userID := 456
		token1, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		token2, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		assert.NotEqual(t, *token1, *token2)
	})
}

func TestVerifyRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should verify valid token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		valid, err := rts.VerifyRefreshToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for non-existent token", func(t *testing.T) {
		userID := 123
		valid, err := rts.VerifyRefreshToken(context.Background(), userID, "non-existent-token-with-correct-length-padding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := rts.VerifyRefreshToken(context.Background(), 0, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = rts.VerifyRefreshToken(context.Background(), -1, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		_, err := rts.VerifyRefreshToken(context.Background(), 123, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 256))
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		_, err := rts.VerifyRefreshToken(context.Background(), 123, longToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		valid, err := rts.VerifyRefreshToken(context.TODO(), userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for revoked token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(context.Background(), *token, userID)
		require.NoError(t, err)

		valid, err := rts.VerifyRefreshToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should return false for wrong user ID", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Try to verify with different user ID
		valid, err := rts.VerifyRefreshToken(context.Background(), 456, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should return false for expired token", func(t *testing.T) {
		// Create config with very short duration
		refreshTokenTTL := "100ms"
		shortConfig := &lib.Config{RefreshTokenTTL: &refreshTokenTTL}
		shortRts, err := service.NewRefreshTokenService(context.Background(), redisDB, shortConfig)
		require.NoError(t, err)

		userID := 789
		token, err := shortRts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(150 * time.Millisecond)

		// Verify token is expired (Redis TTL handles this automatically)
		valid, err := shortRts.VerifyRefreshToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestRevokeRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should revoke token successfully", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(context.Background(), *token, userID)
		require.NoError(t, err)

		valid, err := rts.VerifyRefreshToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		err := rts.RevokeRefreshToken(context.Background(), "some-token", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		err = rts.RevokeRefreshToken(context.Background(), "some-token", -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		err := rts.RevokeRefreshToken(context.Background(), "", 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 256))
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		err := rts.RevokeRefreshToken(context.Background(), longToken, 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should not fail with non-existent token", func(t *testing.T) {
		// Redis DEL is idempotent, no error if key doesn't exist
		err := rts.RevokeRefreshToken(context.Background(), "non-existent-token-with-correct-length-padding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 123)
		require.NoError(t, err)
	})

	t.Run("Should not fail when revoking already revoked token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(context.Background(), *token, userID)
		require.NoError(t, err)

		// Second revocation should not fail (idempotent)
		err = rts.RevokeRefreshToken(context.Background(), *token, userID)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(context.TODO(), *token, userID)
		require.NoError(t, err)
	})
}

func TestRevokeAllUserRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should revoke all user tokens", func(t *testing.T) {
		userID := 123

		token1, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)
		token2, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Create token for another user
		otherUserID := 456
		otherToken, err := rts.CreateRefreshToken(context.Background(), otherUserID)
		require.NoError(t, err)

		// Revoke all tokens for user 123
		err = rts.RevokeAllUserRefreshTokens(context.Background(), userID)
		require.NoError(t, err)

		// Verify tokens for user 123 are revoked
		valid1, err := rts.VerifyRefreshToken(context.Background(), userID, *token1)
		require.NoError(t, err)
		assert.False(t, valid1)

		valid2, err := rts.VerifyRefreshToken(context.Background(), userID, *token2)
		require.NoError(t, err)
		assert.False(t, valid2)

		// Verify other user's token is still valid
		validOther, err := rts.VerifyRefreshToken(context.Background(), otherUserID, *otherToken)
		require.NoError(t, err)
		assert.True(t, validOther)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		err := rts.RevokeAllUserRefreshTokens(context.Background(), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		err = rts.RevokeAllUserRefreshTokens(context.Background(), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should handle user with no tokens", func(t *testing.T) {
		err := rts.RevokeAllUserRefreshTokens(context.Background(), 999)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.RevokeAllUserRefreshTokens(context.TODO(), 123)
		require.NoError(t, err)
	})
}

func TestRevokeAllRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should revoke all tokens for all users", func(t *testing.T) {
		userID1 := 123
		userID2 := 456

		token1, err := rts.CreateRefreshToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := rts.CreateRefreshToken(context.Background(), userID2)
		require.NoError(t, err)

		// Revoke all tokens
		err = rts.RevokeAllRefreshTokens(context.Background())
		require.NoError(t, err)

		// Verify all tokens are revoked
		valid1, err := rts.VerifyRefreshToken(context.Background(), userID1, *token1)
		require.NoError(t, err)
		assert.False(t, valid1)

		valid2, err := rts.VerifyRefreshToken(context.Background(), userID2, *token2)
		require.NoError(t, err)
		assert.False(t, valid2)
	})

	t.Run("Should handle when no tokens exist", func(t *testing.T) {
		err := rts.RevokeAllRefreshTokens(context.Background())
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.RevokeAllRefreshTokens(context.TODO())
		require.NoError(t, err)
	})
}

func TestInvalidConfig(t *testing.T) {
	t.Run("Should fail with invalid duration format", func(t *testing.T) {
		refreshTokenTTL := "invalid-duration"
		invalidConfig := &lib.Config{RefreshTokenTTL: &refreshTokenTTL}
		rts, err := service.NewRefreshTokenService(context.Background(), redisDB, invalidConfig)
		require.NoError(t, err)

		_, err = rts.CreateRefreshToken(context.Background(), 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "time: invalid duration")
	})
}
