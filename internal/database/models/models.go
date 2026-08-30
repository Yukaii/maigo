// Package models contains the small data model used by Maigo Core.
package models

import "time"

// URL represents a shortened link and its lifetime hit count.
type URL struct {
	ID        int64      `json:"id"`
	ShortCode string     `json:"short_code"`
	TargetURL string     `json:"target_url"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Hits      int64      `json:"hits"`
}

// IsExpired reports whether the link is past its optional expiration time.
func (u *URL) IsExpired() bool {
	return u.ExpiresAt != nil && !time.Now().Before(*u.ExpiresAt)
}

// TimeUntilExpiry returns the remaining lifetime, or nil for a permanent or
// already-expired link.
func (u *URL) TimeUntilExpiry() *time.Duration {
	if u.ExpiresAt == nil || u.IsExpired() {
		return nil
	}
	duration := time.Until(*u.ExpiresAt)
	return &duration
}

// CreateURLRequest is the JSON request accepted by the create endpoint.
type CreateURLRequest struct {
	URL       string     `json:"url" binding:"required"`
	Custom    string     `json:"custom,omitempty"`
	TTL       *int64     `json:"ttl,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// PaginationResponse describes one page of links.
type PaginationResponse struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
	Pages    int   `json:"pages"`
}

// URLListResponse is returned by the authenticated list endpoint.
type URLListResponse struct {
	URLs       []URL              `json:"urls"`
	Pagination PaginationResponse `json:"pagination"`
}

// ErrorResponse is the common JSON error shape.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// SuccessResponse is returned by successful mutation endpoints.
type SuccessResponse struct {
	Message string `json:"message"`
}
