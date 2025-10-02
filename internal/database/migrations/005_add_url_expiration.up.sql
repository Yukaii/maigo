-- Add expiration support to URLs table
ALTER TABLE urls ADD COLUMN expires_at TIMESTAMPTZ;

-- Create index for efficient expiration queries
CREATE INDEX IF NOT EXISTS idx_urls_expires_at ON urls (expires_at) WHERE expires_at IS NOT NULL;

-- Create partial index for active (non-null expires_at) URLs
-- Note: We can't use NOW() in index predicate, so we index all URLs with expires_at
-- The application will filter expired URLs at query time
CREATE INDEX IF NOT EXISTS idx_urls_short_code_expires ON urls (short_code, expires_at);