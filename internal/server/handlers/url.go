// Package handlers contains HTTP handlers for Maigo server endpoints.
package handlers

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/database/repository"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/shortener"
)

// URLHandler handles URL shortening operations
type URLHandler struct {
	db        *pgxpool.Pool
	config    *config.Config
	logger    *logger.Logger
	urlRepo   *repository.URLRepository
	shortener *shortener.ShortenerService
}

// NewURLHandler creates a new URL handler
func NewURLHandler(db *pgxpool.Pool, cfg *config.Config, log *logger.Logger) *URLHandler {
	urlRepo := repository.NewURLRepository(db)

	// Create shortener service with existence checker
	shortenerService := shortener.NewShortenerService(
		cfg.App.ShortCodeLength,
		func(shortCode string) (bool, error) {
			return urlRepo.ShortCodeExists(context.Background(), shortCode)
		},
	)

	return &URLHandler{
		db:        db,
		config:    cfg,
		logger:    log,
		urlRepo:   urlRepo,
		shortener: shortenerService,
	}
}

// CreateShortURL creates a new short URL
func (h *URLHandler) CreateShortURL(c *gin.Context) {
	var req models.CreateURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid create URL request", err.Error())
		return
	}

	// Sanitize the URL
	sanitizedURL, err := shortener.SanitizeURL(req.URL)
	if err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid URL: "+err.Error(), nil)
		return
	}

	// Generate short code
	shortCode, err := h.shortener.GenerateShortCode(req.Custom)
	if err != nil {
		h.logger.Error("Failed to generate short code", "error", err, "url", sanitizedURL)
		SendAPIError(c, http.StatusConflict, "conflict", err.Error(), nil)
		return
	}

	// Get user ID from context if authenticated
	var userID *int64
	if id, exists := c.Get("user_id"); exists {
		if uid, ok := id.(int64); ok {
			userID = &uid
		}
	}

	// Create URL in database
	url, err := h.urlRepo.Create(c.Request.Context(), shortCode, sanitizedURL, userID)
	if err != nil {
		h.logger.Error("Failed to create URL", "error", err, "short_code", shortCode)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to create short URL", nil)
		return
	}

	// Build response
	response := map[string]interface{}{
		"id":         url.ID,
		"short_code": url.ShortCode,
		"url":        url.TargetURL,
		"short_url":  "https://" + h.config.App.BaseDomain + "/" + url.ShortCode,
		"created_at": url.CreatedAt.Format(time.RFC3339),
		"hits":       url.Hits,
	}

	if url.UserID != nil {
		response["user_id"] = *url.UserID
	}

	h.logger.Info("Created short URL",
		"short_code", url.ShortCode,
		"target_url", url.TargetURL,
	)

	c.JSON(http.StatusCreated, response)
}

// GetURL retrieves a URL by its short code
func (h *URLHandler) GetURL(c *gin.Context) {
	shortCode := c.Param("code")
	if shortCode == "" {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Short code is required", nil)
		return
	}

	// Validate short code
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid short code format", nil)
		return
	}

	// Get URL from database
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found", "short_code", shortCode, "error", err)
		SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
		return
	}

	// Build response
	response := map[string]interface{}{
		"id":         url.ID,
		"short_code": url.ShortCode,
		"url":        url.TargetURL,
		"short_url":  "https://" + h.config.App.BaseDomain + "/" + url.ShortCode,
		"created_at": url.CreatedAt.Format(time.RFC3339),
		"hits":       url.Hits,
	}

	if url.UserID != nil {
		response["user_id"] = *url.UserID
	}

	c.JSON(http.StatusOK, response)
}

// RedirectShortURL redirects to the target URL
func (h *URLHandler) RedirectShortURL(c *gin.Context) {
	shortCode := c.Param("code")
	if shortCode == "" {
		SendAPIError(c, http.StatusNotFound, "not_found", "Short code not found", nil)
		return
	}

	// Validate short code
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid short code format", nil)
		return
	}

	// Get URL from database
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found", "short_code", shortCode, "error", err)
		SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
		return
	}

	// Increment hit counter (non-blocking)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := h.urlRepo.IncrementHits(ctx, shortCode); err != nil {
			h.logger.Error("Failed to increment hits", "short_code", shortCode, "error", err)
		}
	}()

	h.logger.Info("Redirecting URL",
		"short_code", shortCode,
		"target_url", url.TargetURL,
		"hits", url.Hits,
	)

	// Redirect to target URL
	c.Redirect(http.StatusFound, url.TargetURL)
}

// DeleteURL deletes a short URL
func (h *URLHandler) DeleteURL(c *gin.Context) {
	shortCode := c.Param("code")
	if shortCode == "" {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Short code is required", nil)
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "User authentication required", nil)
		return
	}

	uid, ok := userID.(int64)
	if !ok {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "Invalid user ID", nil)
		return
	}

	// Get URL to verify ownership
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found for deletion", "short_code", shortCode, "error", err)
		SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
		return
	}

	// Check ownership
	if url.UserID == nil || *url.UserID != uid {
		SendAPIError(c, http.StatusForbidden, "forbidden", "You don't have permission to delete this URL", nil)
		return
	}

	// Delete URL
	if err := h.urlRepo.DeleteByUserAndID(c.Request.Context(), uid, url.ID); err != nil {
		h.logger.Error("Failed to delete URL", "short_code", shortCode, "error", err)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to delete URL", nil)
		return
	}

	h.logger.Info("Deleted URL", "short_code", shortCode, "user_id", uid)

	c.JSON(http.StatusOK, models.SuccessResponse{
		Message: "URL deleted successfully",
	})
}

// GetUserURLs retrieves all URLs for the authenticated user
func (h *URLHandler) GetUserURLs(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "User authentication required", nil)
		return
	}

	uid, ok := userID.(int64)
	if !ok {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "Invalid user ID", nil)
		return
	}

	// Parse pagination parameters
	page := 1
	if pageStr := c.Query("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	pageSize := 20
	if pageSizeStr := c.Query("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	// Get URLs for user
	urls, total, err := h.urlRepo.GetByUserID(c.Request.Context(), uid, page, pageSize)
	if err != nil {
		h.logger.Error("Failed to get user URLs", "user_id", uid, "error", err)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to retrieve URLs", nil)
		return
	}

	// Build response URLs
	responseURLs := make([]map[string]interface{}, len(urls))
	for i, url := range urls {
		responseURLs[i] = map[string]interface{}{
			"id":         url.ID,
			"short_code": url.ShortCode,
			"url":        url.TargetURL,
			"short_url":  "https://" + h.config.App.BaseDomain + "/" + url.ShortCode,
			"created_at": url.CreatedAt.Format(time.RFC3339),
			"hits":       url.Hits,
		}
	}

	// Calculate pagination
	pages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		pages++
	}

	response := models.URLListResponse{
		URLs: urls,
		Pagination: models.PaginationResponse{
			Page:     page,
			PageSize: pageSize,
			Total:    total,
			Pages:    pages,
		},
	}

	c.JSON(http.StatusOK, response)
}

// GetURLStats retrieves analytics for a specific short URL
func (h *URLHandler) GetURLStats(c *gin.Context) {
	shortCode := c.Param("code")
	if shortCode == "" {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Short code is required", nil)
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "User authentication required", nil)
		return
	}

	uid, ok := userID.(int64)
	if !ok {
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "Invalid user ID", nil)
		return
	}

	// Validate short code
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid short code format", nil)
		return
	}

	// Get URL from database
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found", "short_code", shortCode, "error", err)
		SendAPIError(c, http.StatusNotFound, "not_found", "Short URL not found", nil)
		return
	}

	// Check ownership
	if url.UserID == nil || *url.UserID != uid {
		SendAPIError(c, http.StatusForbidden, "forbidden",
			"You don't have permission to view statistics for this URL", nil)
		return
	}

	// Build analytics response
	response := map[string]interface{}{
		"id":         url.ID,
		"short_code": url.ShortCode,
		"url":        url.TargetURL,
		"short_url":  "https://" + h.config.App.BaseDomain + "/" + url.ShortCode,
		"hits":       url.Hits,
		"created_at": url.CreatedAt.Format(time.RFC3339),
	}

	// TODO: Add more detailed analytics (daily/weekly/monthly breakdowns)
	// For now, just return basic stats
	response["timeline"] = []map[string]interface{}{
		{
			"date": url.CreatedAt.Format("2006-01-02"),
			"hits": url.Hits,
		},
	}

	h.logger.Info("Retrieved URL statistics", "short_code", shortCode, "user_id", uid)

	c.JSON(http.StatusOK, response)
}
