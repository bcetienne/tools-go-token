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

func setupPasswordResetService(t *testing.T) *service.PasswordResetService {
	prs, err := service.NewPasswordResetService(t.Context(), redisDB, config)
	require.NoError(t, err)

	// Clear all tokens to ensure clean state
	err = prs.RevokeAllPasswordResetTokens(t.Context())
	require.NoError(t, err)

	return prs
}

func TestNewPasswordResetService(t *testing.T) {
	t.Run("Should create service successfully", func(t *testing.T) {
		_, err := service.NewPasswordResetService(t.Context(), redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		_, err := service.NewPasswordResetService(nil, redisDB, config)
		require.NoError(t, err)
	})

	t.Run("Should fail with nil database", func(t *testing.T) {
		_, err := service.NewPasswordResetService(context.Background(), nil, config)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "db is nil")
	})

	t.Run("Should fail with nil password reset ttl", func(t *testing.T) {
		invalidConfig := &lib.Config{PasswordResetTTL: nil}
		_, err := service.NewPasswordResetService(context.Background(), redisDB, invalidConfig)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password reset ttl is nil")
	})
}

func TestCreatePasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should create token successfully", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, *token)
		assert.Equal(t, 32, len(*token))
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := prs.CreatePasswordResetToken(context.Background(), 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = prs.CreatePasswordResetToken(context.Background(), -1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		token, err := prs.CreatePasswordResetToken(nil, 123)
		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, *token)
	})

	t.Run("Should replace existing token when creating new one for same user", func(t *testing.T) {
		userID := 456
		token1, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		token2, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Tokens should be different
		assert.NotEqual(t, *token1, *token2)

		// First token should no longer be valid (replaced by second)
		valid1, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token1)
		require.NoError(t, err)
		assert.False(t, valid1)

		// Second token should be valid
		valid2, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token2)
		require.NoError(t, err)
		assert.True(t, valid2)
	})

	t.Run("Should create token with correct length", func(t *testing.T) {
		userID := 789
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)
		assert.Equal(t, 32, len(*token), "Password reset token should be 32 characters")
	})
}

func TestVerifyPasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should verify valid token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for non-existent token", func(t *testing.T) {
		userID := 123
		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, "abcdefghijklmnopqrstuvwxyz012345")
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		_, err := prs.VerifyPasswordResetToken(context.Background(), 0, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		_, err = prs.VerifyPasswordResetToken(context.Background(), -1, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		_, err := prs.VerifyPasswordResetToken(context.Background(), 123, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 33))
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		_, err := prs.VerifyPasswordResetToken(context.Background(), 123, longToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		valid, err := prs.VerifyPasswordResetToken(nil, userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for revoked token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.RevokePasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)

		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should return false for wrong token with correct user ID", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Try to verify with wrong token but correct userID
		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, "wrongtoken1234567890abcdefghij")
		require.NoError(t, err)
		assert.False(t, valid)

		// Original token should still be valid
		valid, err = prs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should return false for wrong user ID", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Try to verify with different user ID
		valid, err := prs.VerifyPasswordResetToken(context.Background(), 456, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should return false for expired token", func(t *testing.T) {
		// Create config with very short duration
		passwordResetTTL := "100ms"
		shortConfig := &lib.Config{PasswordResetTTL: &passwordResetTTL}
		shortPrs, err := service.NewPasswordResetService(context.Background(), redisDB, shortConfig)
		require.NoError(t, err)

		userID := 789
		token, err := shortPrs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(150 * time.Millisecond)

		// Verify token is expired (Redis TTL handles this automatically)
		valid, err := shortPrs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})
}

func TestRevokePasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should revoke token successfully", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.RevokePasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)

		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("Should fail with invalid user ID", func(t *testing.T) {
		err := prs.RevokePasswordResetToken(context.Background(), 0, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")

		err = prs.RevokePasswordResetToken(context.Background(), -1, "some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid user id")
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		err := prs.RevokePasswordResetToken(context.Background(), 123, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 33))
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		err := prs.RevokePasswordResetToken(context.Background(), 123, longToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should fail with non-existent token", func(t *testing.T) {
		err := prs.RevokePasswordResetToken(context.Background(), 123, "abcdefghijklmnopqrstuvwxyz012345")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should fail with wrong token for user", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Try to revoke with wrong token
		err = prs.RevokePasswordResetToken(context.Background(), userID, "wrongtoken1234567890abcdefghij")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token mismatch")

		// Original token should still be valid
		valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("Should fail when revoking already revoked token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// First revocation
		err = prs.RevokePasswordResetToken(context.Background(), userID, *token)
		require.NoError(t, err)

		// Second revocation should fail
		err = prs.RevokePasswordResetToken(context.Background(), userID, *token)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.RevokePasswordResetToken(nil, userID, *token)
		require.NoError(t, err)
	})
}

func TestRevokeAllPasswordResetTokens(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should revoke all tokens for all users", func(t *testing.T) {
		userID1 := 123
		userID2 := 456

		token1, err := prs.CreatePasswordResetToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := prs.CreatePasswordResetToken(context.Background(), userID2)
		require.NoError(t, err)

		// Revoke all tokens
		err = prs.RevokeAllPasswordResetTokens(context.Background())
		require.NoError(t, err)

		// Verify all tokens are revoked
		valid1, err := prs.VerifyPasswordResetToken(context.Background(), userID1, *token1)
		require.NoError(t, err)
		assert.False(t, valid1)

		valid2, err := prs.VerifyPasswordResetToken(context.Background(), userID2, *token2)
		require.NoError(t, err)
		assert.False(t, valid2)
	})

	t.Run("Should handle when no tokens exist", func(t *testing.T) {
		err := prs.RevokeAllPasswordResetTokens(context.Background())
		require.NoError(t, err)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := prs.RevokeAllPasswordResetTokens(nil)
		require.NoError(t, err)
	})
}

func TestPasswordResetInvalidConfig(t *testing.T) {
	t.Run("Should fail with invalid duration format", func(t *testing.T) {
		passwordResetTTL := "invalid-duration"
		invalidConfig := &lib.Config{PasswordResetTTL: &passwordResetTTL}
		prs, err := service.NewPasswordResetService(context.Background(), redisDB, invalidConfig)
		require.NoError(t, err)

		_, err = prs.CreatePasswordResetToken(context.Background(), 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "time: invalid duration")
	})
}

func TestPasswordResetTokenUniqueness(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should handle multiple users with tokens", func(t *testing.T) {
		// Create tokens for multiple users
		users := []int{100, 200, 300, 400, 500}
		tokens := make(map[int]string) // Map user ID to token value

		for _, userID := range users {
			token, err := prs.CreatePasswordResetToken(context.Background(), userID)
			require.NoError(t, err)
			tokens[userID] = *token
		}

		// Verify all tokens are unique
		tokenSet := make(map[string]bool)
		for _, tokenValue := range tokens {
			if tokenSet[tokenValue] {
				t.Fatal("Duplicate token found across different users")
			}
			tokenSet[tokenValue] = true
		}

		// Verify all tokens are valid for their respective users
		for userID, tokenValue := range tokens {
			valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, tokenValue)
			require.NoError(t, err)
			assert.True(t, valid, "Token for user %d should be valid", userID)
		}
	})
}

func TestPasswordResetConcurrentOperations(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should handle concurrent token creation for same user", func(t *testing.T) {
		userID := 999
		numOperations := 10
		errChan := make(chan error, numOperations)
		tokenChan := make(chan string, numOperations)

		// Create multiple tokens concurrently for the same user
		for i := 0; i < numOperations; i++ {
			go func() {
				token, err := prs.CreatePasswordResetToken(context.Background(), userID)
				if err != nil {
					errChan <- err
				} else {
					tokenChan <- *token
				}
			}()
		}

		// Collect all created tokens
		var tokens []string
		for i := 0; i < numOperations; i++ {
			select {
			case err := <-errChan:
				t.Fatalf("Error creating token: %v", err)
			case token := <-tokenChan:
				tokens = append(tokens, token)
			}
		}

		// All tokens should be unique
		tokenMap := make(map[string]bool)
		for _, token := range tokens {
			if tokenMap[token] {
				t.Fatal("Duplicate token found in concurrent creation")
			}
			tokenMap[token] = true
		}

		// Wait a bit for all operations to settle
		time.Sleep(50 * time.Millisecond)

		// Only ONE token should be valid (the last one written wins)
		validCount := 0
		for _, token := range tokens {
			valid, err := prs.VerifyPasswordResetToken(context.Background(), userID, token)
			require.NoError(t, err)
			if valid {
				validCount++
			}
		}

		assert.Equal(t, 1, validCount, "Only one token should be valid after concurrent creation")
	})
}
