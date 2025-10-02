-- Remove expiration support from URLs table
ALTER TABLE urls DROP COLUMN IF EXISTS expires_at;

-- Remove indexes
DROP INDEX IF EXISTS idx_urls_expires_at;
DROP INDEX IF EXISTS idx_urls_short_code_expires;