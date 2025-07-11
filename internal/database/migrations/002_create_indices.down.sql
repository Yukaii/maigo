-- Drop indices
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_access_tokens_expires_at;
DROP INDEX IF EXISTS idx_access_tokens_user_id;
DROP INDEX IF EXISTS idx_access_tokens_client_id;
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;
DROP INDEX IF EXISTS idx_authorization_codes_user_id;
DROP INDEX IF EXISTS idx_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_domains_user_id;
DROP INDEX IF EXISTS idx_urls_created_at;
DROP INDEX IF EXISTS idx_urls_user_id;
DROP INDEX IF EXISTS idx_urls_short_code;
