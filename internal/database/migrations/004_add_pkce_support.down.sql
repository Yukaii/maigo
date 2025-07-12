-- Remove PKCE support from authorization_codes table
ALTER TABLE authorization_codes 
DROP COLUMN IF EXISTS scope,
DROP COLUMN IF EXISTS code_challenge,
DROP COLUMN IF EXISTS code_challenge_method;

-- Remove indexes
DROP INDEX IF EXISTS idx_authorization_codes_expires_at;
DROP INDEX IF EXISTS idx_authorization_codes_used;
