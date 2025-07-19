package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserModel(t *testing.T) {
	t.Run("User struct fields", func(t *testing.T) {
		now := time.Now()
		user := User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: "hashedpassword",
			CreatedAt:    now,
		}

		assert.Equal(t, int64(1), user.ID)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "hashedpassword", user.PasswordHash)
		assert.Equal(t, now, user.CreatedAt)
	})

	t.Run("User JSON serialization", func(t *testing.T) {
		user := User{
			ID:           1,
			Username:     "testuser",
			Email:        "test@example.com",
			PasswordHash: "hashedpassword",
			CreatedAt:    time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		// PasswordHash should not be included in JSON (json:"-" tag)
		assert.NotContains(t, string(jsonData), "hashedpassword")
		assert.Contains(t, string(jsonData), "testuser")
		assert.Contains(t, string(jsonData), "test@example.com")
	})
}

func TestURLModel(t *testing.T) {
	t.Run("URL struct fields", func(t *testing.T) {
		now := time.Now()
		userID := int64(1)
		url := URL{
			ID:        1,
			ShortCode: "abc123",
			TargetURL: "https://example.com",
			CreatedAt: now,
			Hits:      42,
			UserID:    &userID,
		}

		assert.Equal(t, int64(1), url.ID)
		assert.Equal(t, "abc123", url.ShortCode)
		assert.Equal(t, "https://example.com", url.TargetURL)
		assert.Equal(t, now, url.CreatedAt)
		assert.Equal(t, int64(42), url.Hits)
		assert.Equal(t, &userID, url.UserID)
	})

	t.Run("URL with nil UserID", func(t *testing.T) {
		url := URL{
			UserID: nil,
		}

		assert.Nil(t, url.UserID)
	})

	t.Run("URL JSON serialization", func(t *testing.T) {
		userID := int64(1)
		url := URL{
			ID:        1,
			ShortCode: "abc123",
			TargetURL: "https://example.com",
			CreatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
			Hits:      42,
			UserID:    &userID,
		}

		jsonData, err := json.Marshal(url)
		require.NoError(t, err)

		assert.Contains(t, string(jsonData), "abc123")
		assert.Contains(t, string(jsonData), "https://example.com")
		assert.Contains(t, string(jsonData), "42")
	})
}

func TestOAuthClientModel(t *testing.T) {
	t.Run("OAuthClient struct fields", func(t *testing.T) {
		now := time.Now()
		client := OAuthClient{
			ID:          "client-id",
			Secret:      "client-secret",
			Name:        "Test Client",
			RedirectURI: "https://example.com/callback",
			CreatedAt:   now,
		}

		assert.Equal(t, "client-id", client.ID)
		assert.Equal(t, "client-secret", client.Secret)
		assert.Equal(t, "Test Client", client.Name)
		assert.Equal(t, "https://example.com/callback", client.RedirectURI)
		assert.Equal(t, now, client.CreatedAt)
	})

	t.Run("OAuthClient JSON serialization", func(t *testing.T) {
		client := OAuthClient{
			ID:          "client-id",
			Secret:      "client-secret",
			Name:        "Test Client",
			RedirectURI: "https://example.com/callback",
			CreatedAt:   time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		jsonData, err := json.Marshal(client)
		require.NoError(t, err)

		// Secret should not be included in JSON (json:"-" tag)
		assert.NotContains(t, string(jsonData), "client-secret")
		assert.Contains(t, string(jsonData), "client-id")
		assert.Contains(t, string(jsonData), "Test Client")
	})
}

func TestAuthorizationCodeModel(t *testing.T) {
	t.Run("AuthorizationCode struct fields", func(t *testing.T) {
		now := time.Now()
		expiresAt := now.Add(10 * time.Minute)

		authCode := AuthorizationCode{
			Code:                "auth-code-123",
			ClientID:            "client-id",
			UserID:              1,
			RedirectURI:         "https://example.com/callback",
			Scope:               "read write",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
			ExpiresAt:           expiresAt,
			Used:                false,
			CreatedAt:           now,
		}

		assert.Equal(t, "auth-code-123", authCode.Code)
		assert.Equal(t, "client-id", authCode.ClientID)
		assert.Equal(t, int64(1), authCode.UserID)
		assert.Equal(t, "https://example.com/callback", authCode.RedirectURI)
		assert.Equal(t, "read write", authCode.Scope)
		assert.Equal(t, "challenge", authCode.CodeChallenge)
		assert.Equal(t, "S256", authCode.CodeChallengeMethod)
		assert.Equal(t, expiresAt, authCode.ExpiresAt)
		assert.False(t, authCode.Used)
		assert.Equal(t, now, authCode.CreatedAt)
	})
}

func TestAccessTokenModel(t *testing.T) {
	t.Run("AccessToken struct fields", func(t *testing.T) {
		now := time.Now()
		expiresAt := now.Add(1 * time.Hour)
		refreshToken := "refresh-token-123"

		token := AccessToken{
			Token:        "access-token-123",
			RefreshToken: &refreshToken,
			ClientID:     "client-id",
			UserID:       1,
			Scope:        "read write",
			ExpiresAt:    expiresAt,
			CreatedAt:    now,
		}

		assert.Equal(t, "access-token-123", token.Token)
		assert.Equal(t, &refreshToken, token.RefreshToken)
		assert.Equal(t, "client-id", token.ClientID)
		assert.Equal(t, int64(1), token.UserID)
		assert.Equal(t, "read write", token.Scope)
		assert.Equal(t, expiresAt, token.ExpiresAt)
		assert.Equal(t, now, token.CreatedAt)
	})

	t.Run("AccessToken with nil RefreshToken", func(t *testing.T) {
		token := AccessToken{
			RefreshToken: nil,
		}

		assert.Nil(t, token.RefreshToken)
	})
}

func TestDomainModel(t *testing.T) {
	t.Run("Domain struct fields", func(t *testing.T) {
		now := time.Now()
		sslCert := "ssl-cert-data"
		sslKey := "ssl-key-data"

		domain := Domain{
			ID:        1,
			Domain:    "example.com",
			UserID:    1,
			SSLCert:   &sslCert,
			SSLKey:    &sslKey,
			Verified:  true,
			CreatedAt: now,
		}

		assert.Equal(t, int64(1), domain.ID)
		assert.Equal(t, "example.com", domain.Domain)
		assert.Equal(t, int64(1), domain.UserID)
		assert.Equal(t, &sslCert, domain.SSLCert)
		assert.Equal(t, &sslKey, domain.SSLKey)
		assert.True(t, domain.Verified)
		assert.Equal(t, now, domain.CreatedAt)
	})

	t.Run("Domain JSON serialization", func(t *testing.T) {
		sslCert := "ssl-cert-data"
		sslKey := "ssl-key-data"

		domain := Domain{
			ID:        1,
			Domain:    "example.com",
			UserID:    1,
			SSLCert:   &sslCert,
			SSLKey:    &sslKey,
			Verified:  true,
			CreatedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}

		jsonData, err := json.Marshal(domain)
		require.NoError(t, err)

		// SSL cert and key should not be included in JSON (json:"-" tag)
		assert.NotContains(t, string(jsonData), "ssl-cert-data")
		assert.NotContains(t, string(jsonData), "ssl-key-data")
		assert.Contains(t, string(jsonData), "example.com")
		assert.Contains(t, string(jsonData), "true")
	})
}

func TestCreateUserRequest(t *testing.T) {
	t.Run("CreateUserRequest struct", func(t *testing.T) {
		req := CreateUserRequest{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "securepassword123",
		}

		assert.Equal(t, "testuser", req.Username)
		assert.Equal(t, "test@example.com", req.Email)
		assert.Equal(t, "securepassword123", req.Password)
	})

	t.Run("CreateUserRequest JSON serialization", func(t *testing.T) {
		req := CreateUserRequest{
			Username: "testuser",
			Email:    "test@example.com",
			Password: "securepassword123",
		}

		jsonData, err := json.Marshal(req)
		require.NoError(t, err)

		assert.Contains(t, string(jsonData), "testuser")
		assert.Contains(t, string(jsonData), "test@example.com")
		assert.Contains(t, string(jsonData), "securepassword123")
	})
}

func TestCreateURLRequest(t *testing.T) {
	t.Run("CreateURLRequest with custom code", func(t *testing.T) {
		req := CreateURLRequest{
			URL:    "https://example.com",
			Custom: "mycustom",
		}

		assert.Equal(t, "https://example.com", req.URL)
		assert.Equal(t, "mycustom", req.Custom)
	})

	t.Run("CreateURLRequest without custom code", func(t *testing.T) {
		req := CreateURLRequest{
			URL: "https://example.com",
		}

		assert.Equal(t, "https://example.com", req.URL)
		assert.Empty(t, req.Custom)
	})
}

func TestUpdateURLRequest(t *testing.T) {
	t.Run("UpdateURLRequest with new URL", func(t *testing.T) {
		newURL := "https://newexample.com"
		req := UpdateURLRequest{
			TargetURL: &newURL,
		}

		assert.Equal(t, &newURL, req.TargetURL)
	})

	t.Run("UpdateURLRequest with nil URL", func(t *testing.T) {
		req := UpdateURLRequest{
			TargetURL: nil,
		}

		assert.Nil(t, req.TargetURL)
	})
}

func TestLoginRequest(t *testing.T) {
	t.Run("LoginRequest struct", func(t *testing.T) {
		req := LoginRequest{
			Username: "testuser",
			Password: "password123",
		}

		assert.Equal(t, "testuser", req.Username)
		assert.Equal(t, "password123", req.Password)
	})
}

func TestTokenResponse(t *testing.T) {
	t.Run("TokenResponse struct", func(t *testing.T) {
		resp := TokenResponse{
			AccessToken:  "access-token-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-123",
			Scope:        "read write",
		}

		assert.Equal(t, "access-token-123", resp.AccessToken)
		assert.Equal(t, "Bearer", resp.TokenType)
		assert.Equal(t, 3600, resp.ExpiresIn)
		assert.Equal(t, "refresh-token-123", resp.RefreshToken)
		assert.Equal(t, "read write", resp.Scope)
	})

	t.Run("TokenResponse JSON serialization", func(t *testing.T) {
		resp := TokenResponse{
			AccessToken:  "access-token-123",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
			RefreshToken: "refresh-token-123",
			Scope:        "read write",
		}

		jsonData, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.Contains(t, string(jsonData), "access-token-123")
		assert.Contains(t, string(jsonData), "Bearer")
		assert.Contains(t, string(jsonData), "3600")
		assert.Contains(t, string(jsonData), "refresh-token-123")
		assert.Contains(t, string(jsonData), "read write")
	})
}

func TestErrorResponse(t *testing.T) {
	t.Run("ErrorResponse struct", func(t *testing.T) {
		resp := ErrorResponse{
			Error:   "invalid_request",
			Message: "The request is missing a required parameter",
			Code:    400,
		}

		assert.Equal(t, "invalid_request", resp.Error)
		assert.Equal(t, "The request is missing a required parameter", resp.Message)
		assert.Equal(t, 400, resp.Code)
	})

	t.Run("ErrorResponse JSON serialization", func(t *testing.T) {
		resp := ErrorResponse{
			Error:   "invalid_request",
			Message: "The request is missing a required parameter",
			Code:    400,
		}

		jsonData, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.Contains(t, string(jsonData), "invalid_request")
		assert.Contains(t, string(jsonData), "The request is missing a required parameter")
		assert.Contains(t, string(jsonData), "400")
	})
}

func TestSuccessResponse(t *testing.T) {
	t.Run("SuccessResponse with data", func(t *testing.T) {
		data := map[string]string{"key": "value"}
		resp := SuccessResponse{
			Message: "Operation completed successfully",
			Data:    data,
		}

		assert.Equal(t, "Operation completed successfully", resp.Message)
		assert.Equal(t, data, resp.Data)
	})

	t.Run("SuccessResponse without data", func(t *testing.T) {
		resp := SuccessResponse{
			Message: "Operation completed successfully",
		}

		assert.Equal(t, "Operation completed successfully", resp.Message)
		assert.Nil(t, resp.Data)
	})
}

func TestPaginationResponse(t *testing.T) {
	t.Run("PaginationResponse struct", func(t *testing.T) {
		resp := PaginationResponse{
			Page:     2,
			PageSize: 10,
			Total:    100,
			Pages:    10,
		}

		assert.Equal(t, 2, resp.Page)
		assert.Equal(t, 10, resp.PageSize)
		assert.Equal(t, int64(100), resp.Total)
		assert.Equal(t, 10, resp.Pages)
	})
}

func TestURLListResponse(t *testing.T) {
	t.Run("URLListResponse struct", func(t *testing.T) {
		urls := []URL{
			{ID: 1, ShortCode: "abc123", TargetURL: "https://example1.com"},
			{ID: 2, ShortCode: "def456", TargetURL: "https://example2.com"},
		}

		pagination := PaginationResponse{
			Page:     1,
			PageSize: 10,
			Total:    2,
			Pages:    1,
		}

		resp := URLListResponse{
			URLs:       urls,
			Pagination: pagination,
		}

		assert.Len(t, resp.URLs, 2)
		assert.Equal(t, "abc123", resp.URLs[0].ShortCode)
		assert.Equal(t, "def456", resp.URLs[1].ShortCode)
		assert.Equal(t, pagination, resp.Pagination)
	})

	t.Run("URLListResponse JSON serialization", func(t *testing.T) {
		urls := []URL{
			{ID: 1, ShortCode: "abc123", TargetURL: "https://example1.com"},
		}

		pagination := PaginationResponse{
			Page:     1,
			PageSize: 10,
			Total:    1,
			Pages:    1,
		}

		resp := URLListResponse{
			URLs:       urls,
			Pagination: pagination,
		}

		jsonData, err := json.Marshal(resp)
		require.NoError(t, err)

		assert.Contains(t, string(jsonData), "abc123")
		assert.Contains(t, string(jsonData), "https://example1.com")
		assert.Contains(t, string(jsonData), "pagination")
	})
}

// Test struct tags and validation (these would typically be tested with a validation library)
func TestStructTags(t *testing.T) {
	t.Run("User struct tags", func(t *testing.T) {
		user := User{}

		// These tests verify that the struct tags are properly set
		// In a real application, these would be tested with a validation library

		// Check that the struct has the expected field names for JSON serialization
		jsonData, err := json.Marshal(user)
		require.NoError(t, err)

		var unmarshaled map[string]interface{}
		err = json.Unmarshal(jsonData, &unmarshaled)
		require.NoError(t, err)

		// Verify expected fields exist in JSON
		_, hasID := unmarshaled["id"]
		_, hasUsername := unmarshaled["username"]
		_, hasEmail := unmarshaled["email"]
		_, hasCreatedAt := unmarshaled["created_at"]
		_, hasPasswordHash := unmarshaled["password_hash"]

		assert.True(t, hasID)
		assert.True(t, hasUsername)
		assert.True(t, hasEmail)
		assert.True(t, hasCreatedAt)
		assert.False(t, hasPasswordHash) // Should be excluded due to json:"-"
	})
}
