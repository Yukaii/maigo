-- Add PKCE support to authorization_codes table
ALTER TABLE authorization_codes 
ADD COLUMN scope TEXT DEFAULT '',
ADD COLUMN code_challenge TEXT DEFAULT '',
ADD COLUMN code_challenge_method TEXT DEFAULT '';

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_used ON authorization_codes(used);
