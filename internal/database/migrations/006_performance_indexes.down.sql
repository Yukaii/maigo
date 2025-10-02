-- Remove performance optimization indexes

-- URLs table indexes
DROP INDEX IF EXISTS idx_urls_user_id_created_at;
DROP INDEX IF EXISTS idx_urls_hits;

-- Users table indexes
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_email;

-- OAuth tables indexes
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;
DROP INDEX IF EXISTS idx_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_access_tokens_expires_at;
DROP INDEX IF EXISTS idx_access_tokens_user_id;
DROP INDEX IF EXISTS idx_access_tokens_refresh_token;
DROP INDEX IF EXISTS idx_access_tokens_client_user;
