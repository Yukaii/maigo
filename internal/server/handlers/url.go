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
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: err.Error(),
		})
		return
	}

	// Sanitize the URL
	sanitizedURL, err := shortener.SanitizeURL(req.URL)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid URL: " + err.Error(),
		})
		return
	}

	// Generate short code
	shortCode, err := h.shortener.GenerateShortCode(req.Custom)
	if err != nil {
		h.logger.Error("Failed to generate short code", "error", err, "url", sanitizedURL)
		c.JSON(http.StatusConflict, models.ErrorResponse{
			Error:   "Conflict",
			Message: err.Error(),
		})
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to create short URL",
		})
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: "Short code is required",
		})
		return
	}

	// Validate short code
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid short code format",
		})
		return
	}

	// Get URL from database
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found", "short_code", shortCode, "error", err)
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not Found",
			Message: "Short URL not found",
		})
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
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not Found",
			Message: "Short code not found",
		})
		return
	}

	// Validate short code
	if err := h.shortener.ValidateShortCode(shortCode); err != nil {
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: "Invalid short code format",
		})
		return
	}

	// Get URL from database
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found for redirect", "short_code", shortCode, "error", err)
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not Found",
			Message: "Short URL not found",
		})
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
		c.JSON(http.StatusBadRequest, models.ErrorResponse{
			Error:   "Bad Request",
			Message: "Short code is required",
		})
		return
	}

	// Get user ID from context
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	uid, ok := userID.(int64)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "Invalid user ID",
		})
		return
	}

	// Get URL to verify ownership
	url, err := h.urlRepo.GetByShortCode(c.Request.Context(), shortCode)
	if err != nil {
		h.logger.Warn("URL not found for deletion", "short_code", shortCode, "error", err)
		c.JSON(http.StatusNotFound, models.ErrorResponse{
			Error:   "Not Found",
			Message: "Short URL not found",
		})
		return
	}

	// Check ownership
	if url.UserID == nil || *url.UserID != uid {
		c.JSON(http.StatusForbidden, models.ErrorResponse{
			Error:   "Forbidden",
			Message: "You don't have permission to delete this URL",
		})
		return
	}

	// Delete URL
	if err := h.urlRepo.DeleteByUserAndID(c.Request.Context(), uid, url.ID); err != nil {
		h.logger.Error("Failed to delete URL", "short_code", shortCode, "error", err)
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to delete URL",
		})
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
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "User authentication required",
		})
		return
	}

	uid, ok := userID.(int64)
	if !ok {
		c.JSON(http.StatusUnauthorized, models.ErrorResponse{
			Error:   "Unauthorized",
			Message: "Invalid user ID",
		})
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
		c.JSON(http.StatusInternalServerError, models.ErrorResponse{
			Error:   "Internal Server Error",
			Message: "Failed to retrieve URLs",
		})
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
