package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
)

func TestConnectRedisDisabled(t *testing.T) {
	client, err := ConnectRedis(context.Background(), &config.Config{})

	require.NoError(t, err)
	require.Nil(t, client)
}

func TestConnectRedisHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ConnectRedis(ctx, &config.Config{
		Redis: config.RedisConfig{
			Enabled: true,
			Host:    "127.0.0.1",
			Port:    1,
		},
	})

	require.Error(t, err)
}
