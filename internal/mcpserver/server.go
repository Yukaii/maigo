// Package mcpserver exposes Maigo Core through the local MCP stdio transport.
package mcpserver

import (
	"context"
	"fmt"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yukaii/maigo/internal/database/models"
)

// URLClient is the small HTTP-client surface needed by the MCP tools.
type URLClient interface {
	CreateShortURL(targetURL, custom string, ttl int64) (map[string]any, error)
	ListURLs(page, pageSize int) (*models.URLListResponse, error)
	GetURL(shortCode string) (map[string]any, error)
	GetURLStats(shortCode string) (map[string]any, error)
	DeleteURL(shortCode string) error
}

// New creates an MCP server whose tools call the configured Maigo HTTP API.
func New(client URLClient) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "maigo",
		Version: "1.0.0",
	}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "shorten_url",
		Description: "Create a short URL, optionally with a custom code or TTL in seconds.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ShortenInput) (*mcp.CallToolResult, URLResult, error) {
		_ = ctx
		_ = req
		value, err := client.CreateShortURL(input.URL, input.Custom, input.TTL)
		if err != nil {
			return nil, URLResult{}, err
		}
		return nil, urlResult(value), nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_urls",
		Description: "List the short URLs in this self-hosted Maigo instance.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input ListInput) (*mcp.CallToolResult, ListOutput, error) {
		_ = ctx
		_ = req
		page := input.Page
		if page < 1 {
			page = 1
		}
		pageSize := input.PageSize
		if pageSize < 1 || pageSize > 100 {
			pageSize = 20
		}
		value, err := client.ListURLs(page, pageSize)
		if err != nil {
			return nil, ListOutput{}, err
		}
		output := ListOutput{Pagination: value.Pagination}
		for _, item := range value.URLs {
			output.URLs = append(output.URLs, URLResult{
				ID:        item.ID,
				ShortCode: item.ShortCode,
				TargetURL: item.TargetURL,
				Hits:      item.Hits,
				CreatedAt: item.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
				ExpiresAt: formatTime(item.ExpiresAt),
			})
		}
		return nil, output, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_url",
		Description: "Get metadata for one Maigo short code.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CodeInput) (*mcp.CallToolResult, URLResult, error) {
		_ = ctx
		_ = req
		value, err := client.GetURL(input.ShortCode)
		if err != nil {
			return nil, URLResult{}, err
		}
		return nil, urlResult(value), nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_url_stats",
		Description: "Get the lifetime hit count for one Maigo short code.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CodeInput) (*mcp.CallToolResult, StatsOutput, error) {
		_ = ctx
		_ = req
		value, err := client.GetURLStats(input.ShortCode)
		if err != nil {
			return nil, StatsOutput{}, err
		}
		return nil, statsOutput(value), nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        "delete_url",
		Description: "Delete one Maigo short code.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, input CodeInput) (*mcp.CallToolResult, DeleteOutput, error) {
		_ = ctx
		_ = req
		if err := client.DeleteURL(input.ShortCode); err != nil {
			return nil, DeleteOutput{}, err
		}
		return nil, DeleteOutput{Deleted: true, ShortCode: input.ShortCode}, nil
	})

	return server
}

// Run starts the MCP server on stdin/stdout. Logs must stay off stdout while
// this function is active because stdout is the JSON-RPC transport.
func Run(ctx context.Context, client URLClient) error {
	return New(client).Run(ctx, &mcp.StdioTransport{})
}

type ShortenInput struct {
	URL    string `json:"url" jsonschema:"The target HTTP or HTTPS URL"`
	Custom string `json:"custom,omitempty" jsonschema:"Optional custom short code"`
	TTL    int64  `json:"ttl,omitempty" jsonschema:"Optional lifetime in seconds; minimum 60"`
}

type ListInput struct {
	Page     int `json:"page,omitempty" jsonschema:"Page number starting at 1"`
	PageSize int `json:"page_size,omitempty" jsonschema:"Number of links from 1 to 100"`
}

type CodeInput struct {
	ShortCode string `json:"short_code" jsonschema:"The Maigo short code"`
}

type URLResult struct {
	ID        int64  `json:"id"`
	ShortCode string `json:"short_code"`
	ShortURL  string `json:"short_url,omitempty"`
	TargetURL string `json:"target_url"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Hits      int64  `json:"hits"`
}

type ListOutput struct {
	URLs       []URLResult               `json:"urls"`
	Pagination models.PaginationResponse `json:"pagination"`
}

type StatsOutput struct {
	ShortCode string `json:"short_code"`
	ShortURL  string `json:"short_url"`
	TargetURL string `json:"target_url"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Hits      int64  `json:"hits"`
}

type DeleteOutput struct {
	Deleted   bool   `json:"deleted"`
	ShortCode string `json:"short_code"`
}

func urlResult(value map[string]any) URLResult {
	return URLResult{
		ID:        integer(value["id"]),
		ShortCode: stringValue(value["short_code"]),
		ShortURL:  stringValue(value["short_url"]),
		TargetURL: firstString(value, "target_url", "url"),
		CreatedAt: stringValue(value["created_at"]),
		ExpiresAt: stringValue(value["expires_at"]),
		Hits:      integer(value["hits"]),
	}
}

func statsOutput(value map[string]any) StatsOutput {
	result := urlResult(value)
	return StatsOutput{
		ShortCode: result.ShortCode,
		ShortURL:  result.ShortURL,
		TargetURL: result.TargetURL,
		CreatedAt: result.CreatedAt,
		ExpiresAt: result.ExpiresAt,
		Hits:      result.Hits,
	}
}

func stringValue(value any) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func firstString(value map[string]any, keys ...string) string {
	for _, key := range keys {
		if value[key] != nil {
			return stringValue(value[key])
		}
	}
	return ""
}

func integer(value any) int64 {
	switch number := value.(type) {
	case int64:
		return number
	case int:
		return int64(number)
	case float64:
		return int64(number)
	case float32:
		return int64(number)
	default:
		return 0
	}
}

func formatTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format("2006-01-02T15:04:05Z07:00")
}
