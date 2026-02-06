package service

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/bcetienne/tools-go-token/lib"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	redisTC "github.com/testcontainers/testcontainers-go/modules/redis"
)

var (
	// Redis client for all token services
	redisDB *redis.Client

	// Shared config
	config *lib.Config
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start Redis container
	redisContainer, err := redisTC.Run(ctx,
		"redis:7-alpine",
		redisTC.WithSnapshotting(10, 1),
		redisTC.WithLogLevel(redisTC.LogLevelVerbose),
	)
	if err != nil {
		log.Printf("failed to start Redis container: %s", err)
		return
	}

	defer func() {
		if err = testcontainers.TerminateContainer(redisContainer); err != nil {
			log.Printf("failed to terminate Redis container: %s", err)
		}
	}()

	redisConnStr, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		log.Printf("failed to get Redis connection string: %s", err)
		return
	}

	// Connect to Redis
	opts, err := redis.ParseURL(redisConnStr)
	if err != nil {
		log.Fatalf("Cannot parse Redis URL: %s", err)
	}

	redisDB = redis.NewClient(opts)
	defer func() {
		if err := redisDB.Close(); err != nil {
			log.Printf("failed to close Redis client: %s", err)
		}
	}()

	// Check Redis connection
	err = redisDB.Ping(ctx).Err()
	if err != nil {
		log.Fatalf("Cannot ping Redis: %s", err)
	}

	// Initialize shared config
	refreshTokenTTL := "24h"
	passwordResetTTL := "24h"
	otpTTL := "24h"
	config = &lib.Config{
		RefreshTokenTTL:  &refreshTokenTTL,
		PasswordResetTTL: &passwordResetTTL,
		OTPTTL:           &otpTTL,
	}

	// Run tests
	exitCode := m.Run()

	// Exit with the tests exit code
	os.Exit(exitCode)
}
