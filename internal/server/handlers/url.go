// Package handlers contains the HTTP handlers for Maigo Core.
package handlers

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/database/repository"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/shortener"
)

// URLHandler handles URL shortening operations for the single owner.
type URLHandler struct {
	config    *config.Config
	logger    *logger.Logger
	urlRepo   *repository.URLRepository
	shortener *shortener.ShortenerService
}

// NewURLHandler creates a URL handler backed by SQLite.
func NewURLHandler(db *sql.DB, cfg *config.Config, log *logger.Logger) *URLHandler {
	urlRepo := repository.NewURLRepository(db)
	return &URLHandler{
		config: cfg,
		logger: log,
		shortener: shortener.NewShortenerService(
			cfg.App.ShortCodeLength,
			func(shortCode string) (bool, error) {
				if isReservedShortCode(shortCode) {
					return true, nil
				}
				return urlRepo.ShortCodeExists(context.Background(), shortCode)
			},
		),
		urlRepo: urlRepo,
	}
}

// CreateShortURL creates a short link.
func (h *URLHandler) CreateShortURL(c *gin.Context) {
	var req models.CreateURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid create URL request", err.Error())
		return
	}

	targetURL, err := shortener.SanitizeURL(req.URL)
	if err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid URL: "+err.Error(), nil)
		return
	}
	if req.Custom != "" && isReservedShortCode(req.Custom) {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Custom short code is reserved", nil)
		return
	}

	shortCode, err := h.shortener.GenerateShortCode(req.Custom)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			SendAPIError(c, http.StatusConflict, "conflict", err.Error(), nil)
		} else {
			SendAPIError(c, http.StatusBadRequest, "bad_request", err.Error(), nil)
		}
		return
	}

	expiresAt, err := expirationFromRequest(req)
	if err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", err.Error(), nil)
		return
	}

	url, err := h.urlRepo.Create(c.Request.Context(), shortCode, targetURL, expiresAt)
	if err != nil {
		status := http.StatusInternalServerError
		code := "internal_server_error"
		message := "Failed to create short URL"
		if repository.IsConflict(err) {
			status = http.StatusConflict
			code = "conflict"
			message = "Short code already exists"
		}
		if h.logger != nil {
			h.logger.Error("Failed to create short URL", "short_code", shortCode, "error", err)
		}
		SendAPIError(c, status, code, message, nil)
		return
	}

	if h.logger != nil {
		h.logger.Info("Created short URL", "short_code", shortCode, "target_url", targetURL)
	}
	c.JSON(http.StatusCreated, h.urlResponse(url))
}

func expirationFromRequest(req models.CreateURLRequest) (*time.Time, error) {
	if req.TTL != nil && req.ExpiresAt != nil {
		return nil, errors.New("provide either ttl or expires_at, not both")
	}
	if req.ExpiresAt != nil {
		expiresAt := req.ExpiresAt.UTC()
		if !expiresAt.After(time.Now().UTC()) {
			return nil, errors.New("expires_at must be in the future")
		}
		return &expiresAt, nil
	}
	if req.TTL == nil {
		return nil, nil
	}
	if *req.TTL < 60 {
		return nil, errors.New("ttl must be at least 60 seconds")
	}
	if *req.TTL > math.MaxInt64/int64(time.Second) {
		return nil, errors.New("ttl is too large")
	}
	ttl := time.Duration(*req.TTL) * time.Second
	if ttl <= 0 {
		return nil, errors.New("ttl is too large")
	}
	expiresAt := time.Now().UTC().Add(ttl)
	return &expiresAt, nil
}

// GetURL returns public metadata for a short link.
func (h *URLHandler) GetURL(c *gin.Context) {
	url, err := h.getURL(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, h.urlResponse(url))
}

// GetURLStats returns the lifetime hit count for a short link.
func (h *URLHandler) GetURLStats(c *gin.Context) {
	url, err := h.getURL(c)
	if err != nil {
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"id":         url.ID,
		"short_code": url.ShortCode,
		"url":        url.TargetURL,
		"short_url":  h.config.ShortURL(url.ShortCode),
		"created_at": url.CreatedAt.Format(time.RFC3339),
		"expires_at": expirationString(url.ExpiresAt),
		"hits":       url.Hits,
	})
}

func (h *URLHandler) getURL(c *gin.Context) (*models.URL, error) {
	shortCode := c.Param("code")
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid short code format", nil)
		return nil, err
	}
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if errors.Is(err, repository.ErrNotFound) {
		SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
		return nil, err
	}
	if err != nil {
		if h.logger != nil {
			h.logger.Error("Failed to retrieve short URL", "short_code", shortCode, "error", err)
		}
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to retrieve short URL", nil)
		return nil, err
	}
	return url, nil
}

// RedirectShortURL redirects to the target and increments its hit count.
func (h *URLHandler) RedirectShortURL(c *gin.Context) {
	url, err := h.getURL(c)
	if err != nil {
		return
	}
	if url.IsExpired() {
		SendAPIError(c, http.StatusGone, "gone", "Short URL has expired", nil)
		return
	}

	if err := h.urlRepo.RecordClick(c.Request.Context(), url.ID); err != nil && h.logger != nil {
		h.logger.Error("Failed to record URL click", "short_code", url.ShortCode, "error", err)
	}
	c.Redirect(http.StatusFound, url.TargetURL)
}

// ListURLs returns the owner's links.
func (h *URLHandler) ListURLs(c *gin.Context) {
	page := boundedIntQuery(c, "page", 1, 1, 1_000_000)
	pageSize := boundedIntQuery(c, "page_size", 20, 1, 100)
	urls, total, err := h.urlRepo.List(c.Request.Context(), page, pageSize)
	if err != nil {
		if h.logger != nil {
			h.logger.Error("Failed to list URLs", "error", err)
		}
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to list URLs", nil)
		return
	}
	pages := int((total + int64(pageSize) - 1) / int64(pageSize))
	if total == 0 {
		pages = 0
	}
	c.JSON(http.StatusOK, models.URLListResponse{
		URLs: urls,
		Pagination: models.PaginationResponse{
			Page: page, PageSize: pageSize, Total: total, Pages: pages,
		},
	})
}

// DeleteURL deletes a short link.
func (h *URLHandler) DeleteURL(c *gin.Context) {
	url, err := h.getURL(c)
	if err != nil {
		return
	}
	if err := h.urlRepo.Delete(c.Request.Context(), url.ID); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
			return
		}
		if h.logger != nil {
			h.logger.Error("Failed to delete URL", "short_code", url.ShortCode, "error", err)
		}
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to delete URL", nil)
		return
	}
	c.JSON(http.StatusOK, models.SuccessResponse{Message: "Short URL deleted successfully"})
}

func (h *URLHandler) urlResponse(url *models.URL) gin.H {
	response := gin.H{
		"id":         url.ID,
		"short_code": url.ShortCode,
		"url":        url.TargetURL,
		"target_url": url.TargetURL,
		"short_url":  h.config.ShortURL(url.ShortCode),
		"created_at": url.CreatedAt.Format(time.RFC3339),
		"hits":       url.Hits,
	}
	if expiresAt := expirationString(url.ExpiresAt); expiresAt != nil {
		response["expires_at"] = expiresAt
		response["expired"] = url.IsExpired()
	}
	return response
}

func isReservedShortCode(shortCode string) bool {
	switch strings.ToLower(shortCode) {
	case "api", "health":
		return true
	default:
		return false
	}
}

func expirationString(value *time.Time) *string {
	if value == nil {
		return nil
	}
	formatted := value.UTC().Format(time.RFC3339)
	return &formatted
}

func positiveIntQuery(c *gin.Context, key string, fallback int) int {
	value, err := strconv.Atoi(c.Query(key))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func boundedIntQuery(c *gin.Context, key string, fallback, minimum, maximum int) int {
	value := positiveIntQuery(c, key, fallback)
	if value < minimum || value > maximum {
		return fallback
	}
	return value
}
