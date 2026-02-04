package lib

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

type RedisClientInterface interface {
	InitRedisClient(ctx context.Context) (*redis.Client, error)
}

type RedisClient struct {
	config *Config
}

func NewRedisClient(config *Config) *RedisClient {
	return &RedisClient{
		config: config,
	}
}

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
