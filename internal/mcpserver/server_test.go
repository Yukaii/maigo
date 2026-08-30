package mcpserver

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/database/models"
)

type fakeURLClient struct {
	created bool
}

func (f *fakeURLClient) CreateShortURL(targetURL, custom string, ttl int64) (map[string]any, error) {
	f.created = true
	return map[string]any{
		"id": 1, "short_code": custom, "short_url": "https://sho.rt/" + custom,
		"target_url": targetURL, "created_at": "2026-08-30T00:00:00Z", "hits": float64(0),
	}, nil
}

func (f *fakeURLClient) ListURLs(page, pageSize int) (*models.URLListResponse, error) {
	return &models.URLListResponse{Pagination: models.PaginationResponse{Page: page, PageSize: pageSize}}, nil
}

func (f *fakeURLClient) GetURL(shortCode string) (map[string]any, error) {
	return map[string]any{"short_code": shortCode, "target_url": "https://example.com"}, nil
}

func (f *fakeURLClient) GetURLStats(shortCode string) (map[string]any, error) {
	return map[string]any{"short_code": shortCode, "url": "https://example.com", "hits": float64(3)}, nil
}

func (f *fakeURLClient) DeleteURL(shortCode string) error { return nil }

func TestNewRegistersAndRunsCoreTools(t *testing.T) {
	fake := &fakeURLClient{}
	server := New(fake)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()

	tools, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	require.Len(t, tools.Tools, 5)
	assert.ElementsMatch(t, []string{"shorten_url", "list_urls", "get_url", "get_url_stats", "delete_url"}, toolNames(tools.Tools))

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "shorten_url",
		Arguments: map[string]any{"url": "https://example.com", "custom": "demo"},
	})
	require.NoError(t, err)
	assert.False(t, result.IsError)
	assert.True(t, fake.created)

	cancel()
	assert.ErrorIs(t, <-serverDone, context.Canceled)
}

func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, tool := range tools {
		names = append(names, tool.Name)
	}
	return names
}
