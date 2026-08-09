package storage

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/Jerry-Xin/octo-meeting-service/internal/config"
)

// OpenRedis constructs the Redis client used for leases and idempotency keys.
func OpenRedis(cfg config.RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.Addr,
		Password: cfg.Password,
		DB:       cfg.DB,
	})
}

// RedisChecker reports Redis readiness via PING.
type RedisChecker struct{ Client *redis.Client }

// Name implements health.Checker.
func (c RedisChecker) Name() string { return "redis" }

// Check issues a PING within the caller's context.
func (c RedisChecker) Check(ctx context.Context) error {
	if c.Client == nil {
		return fmt.Errorf("redis not initialized")
	}
	return c.Client.Ping(ctx).Err()
}
