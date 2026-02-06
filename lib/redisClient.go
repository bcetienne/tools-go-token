package lib

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// RedisClientInterface defines the method for Redis client initialization.
type RedisClientInterface interface {
	InitRedisClient(ctx context.Context) (*redis.Client, error)
}

// RedisClient provides Redis client initialization with configuration.
// Wraps the go-redis client with connection pooling and automatic reconnection.
//
// Features:
//   - Connection pooling (managed by go-redis)
//   - Automatic reconnection on connection loss
//   - Ping verification on initialization
//   - Context support for graceful shutdown
type RedisClient struct {
	config *Config
}

// NewRedisClient creates a new Redis client wrapper with configuration.
//
// Parameters:
//   - config: Configuration containing RedisAddr, RedisPwd, and RedisDB
//
// Returns:
//   - *RedisClient: Client wrapper ready for initialization
//
// Example:
//
//	config := lib.NewConfig(...)
//	client := lib.NewRedisClient(config)
//	redisDB, err := client.InitRedisClient(ctx)
func NewRedisClient(config *Config) *RedisClient {
	return &RedisClient{
		config: config,
	}
}

// InitRedisClient establishes a connection to Redis and verifies connectivity.
// Uses Ping to ensure the connection is working before returning the client.
//
// Connection pooling:
//   - Managed automatically by go-redis
//   - Default: 10 connections per CPU
//   - Automatic reconnection on failure
//
// Parameters:
//   - ctx: Context for initialization (uses Background if nil)
//
// Returns:
//   - *redis.Client: Connected Redis client ready for use
//   - error: Connection or authentication errors
//
// Example:
//
//	ctx := context.Background()
//	redisClient, err := client.InitRedisClient(ctx)
//	if err != nil {
//	    log.Fatalf("Failed to connect to Redis: %v", err)
//	}
//	defer redisClient.Close()
//
//	// Use client with services
//	refreshService, _ := service.NewRefreshTokenService(ctx, redisClient, config)
func (rc *RedisClient) InitRedisClient(ctx context.Context) (*redis.Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     rc.config.RedisAddr,
		Password: rc.config.RedisPwd,
		DB:       rc.config.RedisDB,
	})

	_, err := rdb.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to ping Redis at %s: %w", rc.config.RedisAddr, err)
	}

	return rdb, nil
}
