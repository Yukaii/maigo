package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"golang.org/x/crypto/bcrypt"
)

// Server handles OAuth2 operations
type Server struct {
	db     *pgxpool.Pool
	config *config.Config
}

// NewServer creates a new OAuth2 server
func NewServer(db *pgxpool.Pool, cfg *config.Config) *Server {
	return &Server{
		db:     db,
		config: cfg,
	}
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Type     string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// AuthenticateUser validates username/password and returns tokens
func (s *Server) AuthenticateUser(ctx context.Context, username, password string) (*TokenPair, error) {
	// Get user from database
	var user models.User
	query := `SELECT id, username, email, password_hash FROM users WHERE username = $1`
	err := s.db.QueryRow(ctx, query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
	)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Generate tokens
	return s.GenerateTokenPair(ctx, &user)
}

// GenerateTokenPair creates access and refresh tokens for a user
func (s *Server) GenerateTokenPair(ctx context.Context, user *models.User) (*TokenPair, error) {
	now := time.Now()
	
	// Generate access token (1 hour)
	accessClaims := TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Type:     "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   fmt.Sprintf("%d", user.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			Issuer:    s.config.App.Name,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Generate refresh token (30 days)
	refreshClaims := TokenClaims{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Type:     "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   fmt.Sprintf("%d", user.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(30 * 24 * time.Hour)),
			Issuer:    s.config.App.Name,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Store refresh token in database
	_, err = s.db.Exec(ctx, 
		`INSERT INTO sessions (id, user_id, refresh_token, expires_at) 
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (user_id) DO UPDATE SET 
		 refresh_token = $3, expires_at = $4, updated_at = NOW()`,
		refreshClaims.ID, user.ID, refreshTokenString, refreshClaims.ExpiresAt.Time)
	if err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
	}, nil
}

// RefreshAccessToken generates a new access token using a refresh token
func (s *Server) RefreshAccessToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	// Parse and validate refresh token
	token, err := jwt.ParseWithClaims(refreshToken, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid refresh token")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.Type != "refresh" {
		return nil, fmt.Errorf("invalid token type")
	}

	// Verify refresh token exists in database
	var sessionID string
	err = s.db.QueryRow(ctx, 
		`SELECT id FROM sessions WHERE user_id = $1 AND refresh_token = $2 AND expires_at > NOW()`,
		claims.UserID, refreshToken).Scan(&sessionID)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or expired")
	}

	// Get user details
	var user models.User
	err = s.db.QueryRow(ctx, 
		`SELECT id, username, email FROM users WHERE id = $1`,
		claims.UserID).Scan(&user.ID, &user.Username, &user.Email)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new token pair
	return s.GenerateTokenPair(ctx, &user)
}

// RevokeToken invalidates a refresh token
func (s *Server) RevokeToken(ctx context.Context, userID int64) error {
	_, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
	return err
}

// ValidateAccessToken validates an access token and returns user info
func (s *Server) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid access token")
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || claims.Type != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	return claims, nil
}

// RegisterUser creates a new user account
func (s *Server) RegisterUser(ctx context.Context, username, email, password string) (*models.User, error) {
	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
	}

	query := `
		INSERT INTO users (username, email, password_hash, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id, created_at`
	
	err = s.db.QueryRow(ctx, query, user.Username, user.Email, user.PasswordHash).
		Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// GenerateRandomString generates a cryptographically secure random string
func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
