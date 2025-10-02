-- Performance optimization indexes for Maigo

-- URLs table indexes
-- Index for user URL lookups (list user's URLs)
CREATE INDEX IF NOT EXISTS idx_urls_user_id_created_at ON urls (user_id, created_at DESC);

-- Index for hit tracking and popular URLs
CREATE INDEX IF NOT EXISTS idx_urls_hits ON urls (hits DESC) WHERE hits > 0;

-- Users table indexes
-- Index for username lookups (login)
CREATE INDEX IF NOT EXISTS idx_users_username ON users (username);

-- Index for email lookups (registration, password reset)
CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);

-- OAuth tables indexes
-- Index for authorization code lookups and cleanup
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes (expires_at);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes (user_id);

-- Index for access token lookups and cleanup
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens (expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_refresh_token ON access_tokens (refresh_token);

-- Composite index for OAuth client + user lookups
CREATE INDEX IF NOT EXISTS idx_access_tokens_client_user ON access_tokens (client_id, user_id);

-- ANALYZE tables to update statistics for query planner
ANALYZE users;
ANALYZE urls;
ANALYZE oauth_clients;
ANALYZE authorization_codes;
ANALYZE access_tokens;
