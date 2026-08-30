package server

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yukaii/maigo/internal/config"
)

const redisConnectTimeout = 30 * time.Second

// ConnectRedis creates and verifies the optional Redis connection used for
// distributed rate limiting. Disabled Redis returns a nil client without
// opening a connection.
func ConnectRedis(ctx context.Context, cfg *config.Config) (*redis.Client, error) {
	if !cfg.Redis.Enabled {
		return nil, nil
	}

	client := redis.NewClient(&redis.Options{
		Addr:     net.JoinHostPort(cfg.Redis.Host, strconv.Itoa(cfg.Redis.Port)),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	pingCtx, cancel := context.WithTimeout(ctx, redisConnectTimeout)
	defer cancel()

	var lastErr error
	for {
		if err := client.Ping(pingCtx).Err(); err == nil {
			return client, nil
		} else {
			lastErr = err
		}

		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-pingCtx.Done():
			timer.Stop()
			if closeErr := client.Close(); closeErr != nil {
				return nil, fmt.Errorf("redis health check failed: %w (close: %v)", lastErr, closeErr)
			}
			return nil, fmt.Errorf("redis health check failed: %w", lastErr)
		case <-timer.C:
		}
	}
}
