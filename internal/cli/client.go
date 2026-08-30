// Package cli implements the Maigo Core command-line interface.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
)

// APIClient is a small HTTP client for a Maigo Core installation.
type APIClient struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// NewAPIClient creates a client from the configured public URL and API key.
func NewAPIClient(cfg *config.Config) *APIClient {
	return &APIClient{
		BaseURL: strings.TrimRight(cfg.App.PublicURL, "/"),
		APIKey:  cfg.Auth.APIKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// CreateShortURL creates a short link through the management API.
func (c *APIClient) CreateShortURL(targetURL, custom string, ttl int64) (map[string]any, error) {
	body := map[string]any{"url": targetURL}
	if custom != "" {
		body["custom"] = custom
	}
	if ttl != 0 {
		body["ttl"] = ttl
	}

	var response map[string]any
	if err := c.doJSON(http.MethodPost, "/api/v1/urls", body, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// ListURLs lists all links owned by this installation.
func (c *APIClient) ListURLs(page, pageSize int) (*models.URLListResponse, error) {
	path := fmt.Sprintf("/api/v1/urls?page=%d&page_size=%d", page, pageSize)
	var response models.URLListResponse
	if err := c.doJSON(http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return &response, nil
}

// GetURL returns metadata for one short code.
func (c *APIClient) GetURL(shortCode string) (map[string]any, error) {
	var response map[string]any
	if err := c.doJSON(http.MethodGet, "/api/v1/urls/"+url.PathEscape(shortCode), nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// GetURLStats returns lifetime hit statistics for one short code.
func (c *APIClient) GetURLStats(shortCode string) (map[string]any, error) {
	var response map[string]any
	path := "/api/v1/urls/" + url.PathEscape(shortCode) + "/stats"
	if err := c.doJSON(http.MethodGet, path, nil, &response); err != nil {
		return nil, err
	}
	return response, nil
}

// DeleteURL deletes one short code.
func (c *APIClient) DeleteURL(shortCode string) error {
	path := "/api/v1/urls/" + url.PathEscape(shortCode)
	return c.doJSON(http.MethodDelete, path, nil, &struct{}{})
}

func (c *APIClient) doJSON(method, path string, body, result any) (err error) {
	if c.BaseURL == "" {
		return fmt.Errorf("server URL is not configured")
	}

	var requestBody io.Reader
	if body != nil {
		encoded, marshalErr := json.Marshal(body)
		if marshalErr != nil {
			return fmt.Errorf("encode request: %w", marshalErr)
		}
		requestBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, requestBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close response: %w", closeErr)
		}
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		var apiError models.ErrorResponse
		if json.Unmarshal(responseBody, &apiError) == nil && apiError.Message != "" {
			return fmt.Errorf("%s: %s (HTTP %d)", apiError.Error, apiError.Message, resp.StatusCode)
		}
		return fmt.Errorf("request failed with HTTP %d", resp.StatusCode)
	}
	if result == nil || len(responseBody) == 0 {
		return nil
	}
	if err := json.Unmarshal(responseBody, result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
