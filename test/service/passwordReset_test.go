package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/bcetienne/tools-go-token/service"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupPasswordResetService(t *testing.T) *service.PasswordResetService {
	// NewPasswordResetService will create the schema and table on the first call.
	prs, err := service.NewPasswordResetService(t.Context(), db, config)
	require.NoError(t, err)

	// We clear the table to ensure the test starts from a clean state.
	err = prs.FlushPasswordResetTokens(t.Context())
	require.NoError(t, err)

	return prs
}

func TestNewPasswordResetService(t *testing.T) {
	t.Run("Should create schema and table if not exists", func(t *testing.T) {
		_, err := service.NewPasswordResetService(t.Context(), db, config)
		require.NoError(t, err)

		// Verify that the schema and table exist
		var exists bool
		query := fmt.Sprintf(`SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = '%s' AND table_name = '%s'
		)`, schema, table)
		err = db.QueryRow(query).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, fmt.Sprintf("The table '%s' should exist in the '%s' schema", table, schema))
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		_, err := service.NewPasswordResetService(nil, db, config)
		require.NoError(t, err)
	})

	t.Run("Should fail with nil database", func(t *testing.T) {
		_, err := service.NewPasswordResetService(context.Background(), nil, config)
		require.Error(t, err)
	})
}

func TestCreatePasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should create token successfully", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, userID, token.UserID)
		assert.NotEmpty(t, token.TokenValue)
		assert.Equal(t, "PASSWORD_RESET", token.TokenType)
		assert.True(t, token.ExpiresAt.After(time.Now()))
		assert.Greater(t, token.TokenID, 0)
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
	})

	t.Run("Should create different tokens for same user", func(t *testing.T) {
		userID := 456
		token1, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		token2, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		assert.NotEqual(t, token1.TokenValue, token2.TokenValue)
		assert.NotEqual(t, token1.TokenID, token2.TokenID)
	})

	t.Run("Should create token with correct length", func(t *testing.T) {
		userID := 789
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)
		assert.Equal(t, 32, len(token.TokenValue), "Password reset token should be 32 characters")
	})
}

func TestVerifyPasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should verify valid token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		exists, err := prs.VerifyPasswordResetToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.NotNil(t, exists)
		assert.True(t, *exists)
	})

	t.Run("Should return false for non-existent token", func(t *testing.T) {
		exists, err := prs.VerifyPasswordResetToken(context.Background(), "non-existent-token")
		require.NoError(t, err)
		assert.NotNil(t, exists)
		assert.False(t, *exists)
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		_, err := prs.VerifyPasswordResetToken(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 33)) // Plus long que passwordResetTokenMaxLength (32)
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		_, err := prs.VerifyPasswordResetToken(context.Background(), longToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		exists, err := prs.VerifyPasswordResetToken(nil, token.TokenValue)
		require.NoError(t, err)
		assert.True(t, *exists)
	})

	t.Run("Should return false for revoked token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Révoquer le token
		err = prs.RevokePasswordResetToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Vérifier qu'il n'est plus valide
		exists, err := prs.VerifyPasswordResetToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
	})
}

func TestRevokePasswordResetToken(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should revoke token successfully", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.RevokePasswordResetToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Vérifier que le token n'est plus valide
		exists, err := prs.VerifyPasswordResetToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		err := prs.RevokePasswordResetToken(context.Background(), "", 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 33))
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		err := prs.RevokePasswordResetToken(context.Background(), longToken, 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should fail with non-existent token", func(t *testing.T) {
		err := prs.RevokePasswordResetToken(context.Background(), "non-existent-token", 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should fail when revoking already revoked token", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Première révocation
		err = prs.RevokePasswordResetToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Deuxième révocation (devrait échouer)
		err = prs.RevokePasswordResetToken(context.Background(), token.TokenValue, userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.RevokePasswordResetToken(nil, token.TokenValue, userID)
		require.NoError(t, err)
	})
}

func TestRevokeAllUserPasswordResetTokens(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should revoke all user tokens", func(t *testing.T) {
		userID := 123

		// Créer plusieurs tokens pour le même utilisateur
		token1, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)
		token2, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Créer un token pour un autre utilisateur
		otherUserID := 456
		otherToken, err := prs.CreatePasswordResetToken(context.Background(), otherUserID)
		require.NoError(t, err)

		// Révoquer tous les tokens de l'utilisateur 123
		err = prs.RevokeAllUserPasswordResetTokens(context.Background(), userID)
		require.NoError(t, err)

		// Vérifier que les tokens de l'utilisateur 123 sont révoqués
		exists1, err := prs.VerifyPasswordResetToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := prs.VerifyPasswordResetToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)

		// Vérifier que le token de l'autre utilisateur est toujours valide
		existsOther, err := prs.VerifyPasswordResetToken(context.Background(), otherToken.TokenValue)
		require.NoError(t, err)
		assert.True(t, *existsOther)
	})

	t.Run("Should handle user with no tokens", func(t *testing.T) {
		err := prs.RevokeAllUserPasswordResetTokens(context.Background(), 999)
		require.NoError(t, err) // Ne devrait pas échouer même si l'utilisateur n'a pas de tokens
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := prs.RevokeAllUserPasswordResetTokens(nil, 123)
		require.NoError(t, err)
	})
}

func TestDeleteExpiredPasswordResetTokens(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should delete expired tokens", func(t *testing.T) {
		// Créer une config avec expiration très courte
		tokenExpiry := "1ms"
		shortConfig := &lib.Config{TokenExpiry: &tokenExpiry}
		shortPrs, err := service.NewPasswordResetService(context.Background(), db, shortConfig)
		require.NoError(t, err)

		userID := 123
		token, err := shortPrs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		// Attendre que le token expire
		time.Sleep(10 * time.Millisecond)

		// Supprimer les tokens expirés
		err = shortPrs.DeleteExpiredPasswordResetTokens(context.Background())
		require.NoError(t, err)

		// Vérifier que le token a été supprimé (et non juste marqué comme expiré)
		exists, err := shortPrs.VerifyPasswordResetToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
	})

	t.Run("Should not delete valid tokens", func(t *testing.T) {
		userID := 123
		token, err := prs.CreatePasswordResetToken(context.Background(), userID)
		require.NoError(t, err)

		err = prs.DeleteExpiredPasswordResetTokens(context.Background())
		require.NoError(t, err)

		// Le token valide devrait toujours exister
		exists, err := prs.VerifyPasswordResetToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.True(t, *exists)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := prs.DeleteExpiredPasswordResetTokens(nil)
		require.NoError(t, err)
	})
}

func TestFlushPasswordResetTokens(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should delete all tokens", func(t *testing.T) {
		// Créer plusieurs tokens
		userID1 := 123
		userID2 := 456
		token1, err := prs.CreatePasswordResetToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := prs.CreatePasswordResetToken(context.Background(), userID2)
		require.NoError(t, err)

		// Supprimer tous les tokens
		err = prs.FlushPasswordResetTokens(context.Background())
		require.NoError(t, err)

		// Vérifier que tous les tokens ont été supprimés
		exists1, err := prs.VerifyPasswordResetToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := prs.VerifyPasswordResetToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)
	})

	t.Run("Should handle empty table", func(t *testing.T) {
		err := prs.FlushPasswordResetTokens(context.Background())
		require.NoError(t, err) // Ne devrait pas échouer sur une table vide
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := prs.FlushPasswordResetTokens(nil)
		require.NoError(t, err)
	})
}

func TestFlushUserPasswordResetTokens(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should delete all tokens for specific user", func(t *testing.T) {
		userID1 := 123
		userID2 := 456

		// Créer des tokens pour les deux utilisateurs
		token1, err := prs.CreatePasswordResetToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := prs.CreatePasswordResetToken(context.Background(), userID1)
		require.NoError(t, err)
		otherToken, err := prs.CreatePasswordResetToken(context.Background(), userID2)
		require.NoError(t, err)

		// Supprimer tous les tokens de l'utilisateur 1
		err = prs.FlushUserPasswordResetTokens(context.Background(), userID1)
		require.NoError(t, err)

		// Vérifier que les tokens de l'utilisateur 1 ont été supprimés
		exists1, err := prs.VerifyPasswordResetToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := prs.VerifyPasswordResetToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)

		// Vérifier que le token de l'utilisateur 2 existe toujours
		existsOther, err := prs.VerifyPasswordResetToken(context.Background(), otherToken.TokenValue)
		require.NoError(t, err)
		assert.True(t, *existsOther)
	})

	t.Run("Should handle user with no tokens", func(t *testing.T) {
		err := prs.FlushUserPasswordResetTokens(context.Background(), 999)
		require.NoError(t, err) // Ne devrait pas échouer même si l'utilisateur n'a pas de tokens
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := prs.FlushUserPasswordResetTokens(nil, 123)
		require.NoError(t, err)
	})
}

func TestPasswordResetInvalidConfig(t *testing.T) {
	t.Run("Should fail with invalid duration format", func(t *testing.T) {
		tokenExpiry := "invalid-duration"
		invalidConfig := &lib.Config{TokenExpiry: &tokenExpiry}
		prs, err := service.NewPasswordResetService(context.Background(), db, invalidConfig)
		require.NoError(t, err) // Le service se crée bien

		// Mais la création de token échoue
		_, err = prs.CreatePasswordResetToken(context.Background(), 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "time: invalid duration")
	})
}

func TestPasswordResetTokenUniqueness(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should handle multiple users with tokens", func(t *testing.T) {
		// Créer des tokens pour plusieurs utilisateurs
		users := []int{100, 200, 300, 400, 500}
		tokens := make(map[string]int) // Map token value to user ID

		for _, userID := range users {
			token, err := prs.CreatePasswordResetToken(context.Background(), userID)
			require.NoError(t, err)

			// Vérifier que le token est unique
			if existingUserID, exists := tokens[token.TokenValue]; exists {
				t.Fatalf("Token collision detected: same token for users %d and %d", existingUserID, userID)
			}
			tokens[token.TokenValue] = userID
		}

		// Vérifier que tous les tokens sont valides
		for tokenValue, userID := range tokens {
			exists, err := prs.VerifyPasswordResetToken(context.Background(), tokenValue)
			require.NoError(t, err)
			assert.True(t, *exists, "Token for user %d should be valid", userID)
		}
	})
}

func TestPasswordResetConcurrentOperations(t *testing.T) {
	prs := setupPasswordResetService(t)

	t.Run("Should handle concurrent token creation", func(t *testing.T) {
		userID := 999
		numTokens := 10
		errChan := make(chan error, numTokens)
		tokenChan := make(chan string, numTokens)

		// Créer plusieurs tokens en parallèle
		for i := 0; i < numTokens; i++ {
			go func() {
				token, err := prs.CreatePasswordResetToken(context.Background(), userID)
				if err != nil {
					errChan <- err
				} else {
					tokenChan <- token.TokenValue
				}
			}()
		}

		// Collecter les résultats
		var tokens []string
		for i := 0; i < numTokens; i++ {
			select {
			case err := <-errChan:
				t.Fatalf("Error creating token: %v", err)
			case token := <-tokenChan:
				tokens = append(tokens, token)
			}
		}

		// Vérifier que tous les tokens sont uniques
		tokenMap := make(map[string]bool)
		for _, token := range tokens {
			if tokenMap[token] {
				t.Fatal("Duplicate token found in concurrent creation")
			}
			tokenMap[token] = true
		}

		// Vérifier que tous les tokens sont valides
		for _, token := range tokens {
			exists, err := prs.VerifyPasswordResetToken(context.Background(), token)
			require.NoError(t, err)
			assert.True(t, *exists)
		}
	})
}
