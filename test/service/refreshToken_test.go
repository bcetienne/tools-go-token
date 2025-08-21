package service

import (
	"context"
	"database/sql"
	"log"
	"os"
	"testing"
	"time"

	libRefreshToken "github.com/bcetienne/tools-go-token/lib/refresh-token"
	"github.com/bcetienne/tools-go-token/service"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	db          *sql.DB
	config      *libRefreshToken.Config
	serviceEnum string = "REFRESH_TOKEN"
	schema      string = "go_auth"
	table       string = "refresh_token"
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	database := "go_auth_module_test"
	username := "user"
	password := "password"

	postgresContainer, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase(database),
		postgres.WithUsername(username),
		postgres.WithPassword(password),
		postgres.BasicWaitStrategies(),
	)

	defer func() {
		if err = testcontainers.TerminateContainer(postgresContainer); err != nil {
			log.Printf("failed to terminate container: %s", err)
		}
	}()
	if err != nil {
		log.Printf("failed to start container: %s", err)
		return
	}

	connStr, err := postgresContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Printf("failed to get connection string: %s", err)
		return
	}

	// Connect to database
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Cannot to connect to database: %s", err)
	}
	defer db.Close()

	// Check that the connection is established
	err = db.Ping()
	if err != nil {
		log.Fatalf("Cannot ping database: %s", err)
	}

	// Initialize fake config
	config = &libRefreshToken.Config{RefreshTokenExpiry: "24h"}

	// Run tests
	exitCode := m.Run()

	// Exit with the tests exit code
	os.Exit(exitCode)
}

func setupService(t *testing.T) *service.RefreshTokenService {
	// NewRefreshTokenService will create the schema and table on the first call.
	rts, err := service.NewRefreshTokenService(t.Context(), db, config)
	require.NoError(t, err)

	// We clear the table to ensure the test starts from a clean state.
	err = rts.FlushRefreshTokens(t.Context())
	require.NoError(t, err)

	return rts
}

func TestNewRefreshTokenService(t *testing.T) {
	t.Run("Should create schema and table if not exists", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(t.Context(), db, config)
		require.NoError(t, err)

		// Verify that the schema and table exist
		var exists bool
		query := `
		SELECT EXISTS (
			SELECT FROM information_schema.tables
			WHERE table_schema = 'go_auth' AND table_name = 'refresh_token'
		)`
		err = db.QueryRow(query).Scan(&exists)
		require.NoError(t, err)
		assert.True(t, exists, "The table 'refresh_token' should exist in the 'go_auth' schema")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(nil, db, config)
		require.NoError(t, err)
	})

	t.Run("Should fail with nil database", func(t *testing.T) {
		_, err := service.NewRefreshTokenService(context.Background(), nil, config)
		require.Error(t, err)
	})
}

func TestCreateRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should create token successfully", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)

		require.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, userID, token.UserID)
		assert.NotEmpty(t, token.TokenValue)
		assert.Equal(t, "REFRESH_TOKEN", token.TokenType)
		assert.True(t, token.ExpiresAt.After(time.Now()))
		assert.Greater(t, token.TokenID, 0)
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
		token, err := rts.CreateRefreshToken(nil, 123)
		require.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("Should create different tokens for same user", func(t *testing.T) {
		userID := 456
		token1, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		token2, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		assert.NotEqual(t, token1.TokenValue, token2.TokenValue)
		assert.NotEqual(t, token1.TokenID, token2.TokenID)
	})
}

func TestVerifyRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should verify valid token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		exists, err := rts.VerifyRefreshToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.NotNil(t, exists)
		assert.True(t, *exists)
	})

	t.Run("Should return false for non-existent token", func(t *testing.T) {
		exists, err := rts.VerifyRefreshToken(context.Background(), "non-existent-token")
		require.NoError(t, err)
		assert.NotNil(t, exists)
		assert.False(t, *exists)
	})

	t.Run("Should fail with empty token", func(t *testing.T) {
		_, err := rts.VerifyRefreshToken(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Should fail with token too long", func(t *testing.T) {
		longToken := string(make([]byte, 256)) // Plus long que tokenMaxLength (255)
		for i := range longToken {
			longToken = longToken[:i] + "a" + longToken[i+1:]
		}

		_, err := rts.VerifyRefreshToken(context.Background(), longToken)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token too long")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		exists, err := rts.VerifyRefreshToken(nil, token.TokenValue)
		require.NoError(t, err)
		assert.True(t, *exists)
	})

	t.Run("Should return false for revoked token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Révoquer le token
		err = rts.RevokeRefreshToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Vérifier qu'il n'est plus valide
		exists, err := rts.VerifyRefreshToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
	})
}

func TestRevokeRefreshToken(t *testing.T) {
	rts := setupService(t)

	t.Run("Should revoke token successfully", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Vérifier que le token n'est plus valide
		exists, err := rts.VerifyRefreshToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
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

	t.Run("Should fail with non-existent token", func(t *testing.T) {
		err := rts.RevokeRefreshToken(context.Background(), "non-existent-token", 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should fail when revoking already revoked token", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Première révocation
		err = rts.RevokeRefreshToken(context.Background(), token.TokenValue, userID)
		require.NoError(t, err)

		// Deuxième révocation (devrait échouer)
		err = rts.RevokeRefreshToken(context.Background(), token.TokenValue, userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token not found or already revoked")
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.RevokeRefreshToken(nil, token.TokenValue, userID)
		require.NoError(t, err)
	})
}

func TestRevokeAllUserRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should revoke all user tokens", func(t *testing.T) {
		userID := 123

		// Créer plusieurs tokens pour le même utilisateur
		token1, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)
		token2, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Créer un token pour un autre utilisateur
		otherUserID := 456
		otherToken, err := rts.CreateRefreshToken(context.Background(), otherUserID)
		require.NoError(t, err)

		// Révoquer tous les tokens de l'utilisateur 123
		err = rts.RevokeAllUserRefreshTokens(context.Background(), userID)
		require.NoError(t, err)

		// Vérifier que les tokens de l'utilisateur 123 sont révoqués
		exists1, err := rts.VerifyRefreshToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := rts.VerifyRefreshToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)

		// Vérifier que le token de l'autre utilisateur est toujours valide
		existsOther, err := rts.VerifyRefreshToken(context.Background(), otherToken.TokenValue)
		require.NoError(t, err)
		assert.True(t, *existsOther)
	})

	t.Run("Should handle user with no tokens", func(t *testing.T) {
		err := rts.RevokeAllUserRefreshTokens(context.Background(), 999)
		require.NoError(t, err) // Ne devrait pas échouer même si l'utilisateur n'a pas de tokens
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.RevokeAllUserRefreshTokens(nil, 123)
		require.NoError(t, err)
	})
}

func TestDeleteExpiredRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should delete expired tokens", func(t *testing.T) {
		// Créer une config avec expiration très courte
		shortConfig := &libRefreshToken.Config{RefreshTokenExpiry: "1ms"}
		shortRts, err := service.NewRefreshTokenService(context.Background(), db, shortConfig)
		require.NoError(t, err)

		userID := 123
		token, err := shortRts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		// Attendre que le token expire
		time.Sleep(10 * time.Millisecond)

		// Supprimer les tokens expirés
		err = shortRts.DeleteExpiredRefreshTokens(context.Background())
		require.NoError(t, err)

		// Vérifier que le token a été supprimé (et non juste marqué comme expiré)
		exists, err := shortRts.VerifyRefreshToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists)
	})

	t.Run("Should not delete valid tokens", func(t *testing.T) {
		userID := 123
		token, err := rts.CreateRefreshToken(context.Background(), userID)
		require.NoError(t, err)

		err = rts.DeleteExpiredRefreshTokens(context.Background())
		require.NoError(t, err)

		// Le token valide devrait toujours exister
		exists, err := rts.VerifyRefreshToken(context.Background(), token.TokenValue)
		require.NoError(t, err)
		assert.True(t, *exists)
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.DeleteExpiredRefreshTokens(nil)
		require.NoError(t, err)
	})
}

func TestFlushRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should delete all tokens", func(t *testing.T) {
		// Créer plusieurs tokens
		userID1 := 123
		userID2 := 456
		token1, err := rts.CreateRefreshToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := rts.CreateRefreshToken(context.Background(), userID2)
		require.NoError(t, err)

		// Supprimer tous les tokens
		err = rts.FlushRefreshTokens(context.Background())
		require.NoError(t, err)

		// Vérifier que tous les tokens ont été supprimés
		exists1, err := rts.VerifyRefreshToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := rts.VerifyRefreshToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)
	})

	t.Run("Should handle empty table", func(t *testing.T) {
		err := rts.FlushRefreshTokens(context.Background())
		require.NoError(t, err) // Ne devrait pas échouer sur une table vide
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.FlushRefreshTokens(nil)
		require.NoError(t, err)
	})
}

func TestFlushUserRefreshTokens(t *testing.T) {
	rts := setupService(t)

	t.Run("Should delete all tokens for specific user", func(t *testing.T) {
		userID1 := 123
		userID2 := 456

		// Créer des tokens pour les deux utilisateurs
		token1, err := rts.CreateRefreshToken(context.Background(), userID1)
		require.NoError(t, err)
		token2, err := rts.CreateRefreshToken(context.Background(), userID1)
		require.NoError(t, err)
		otherToken, err := rts.CreateRefreshToken(context.Background(), userID2)
		require.NoError(t, err)

		// Supprimer tous les tokens de l'utilisateur 1
		err = rts.FlushUserRefreshTokens(context.Background(), userID1)
		require.NoError(t, err)

		// Vérifier que les tokens de l'utilisateur 1 ont été supprimés
		exists1, err := rts.VerifyRefreshToken(context.Background(), token1.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists1)

		exists2, err := rts.VerifyRefreshToken(context.Background(), token2.TokenValue)
		require.NoError(t, err)
		assert.False(t, *exists2)

		// Vérifier que le token de l'utilisateur 2 existe toujours
		existsOther, err := rts.VerifyRefreshToken(context.Background(), otherToken.TokenValue)
		require.NoError(t, err)
		assert.True(t, *existsOther)
	})

	t.Run("Should handle user with no tokens", func(t *testing.T) {
		err := rts.FlushUserRefreshTokens(context.Background(), 999)
		require.NoError(t, err) // Ne devrait pas échouer même si l'utilisateur n'a pas de tokens
	})

	t.Run("Should handle nil context", func(t *testing.T) {
		err := rts.FlushUserRefreshTokens(nil, 123)
		require.NoError(t, err)
	})
}

func TestInvalidConfig(t *testing.T) {
	t.Run("Should fail with invalid duration format", func(t *testing.T) {
		invalidConfig := &libRefreshToken.Config{RefreshTokenExpiry: "invalid-duration"}
		rts, err := service.NewRefreshTokenService(context.Background(), db, invalidConfig)
		require.NoError(t, err) // Le service se crée bien

		// Mais la création de token échoue
		_, err = rts.CreateRefreshToken(context.Background(), 123)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "time: invalid duration")
	})
}
