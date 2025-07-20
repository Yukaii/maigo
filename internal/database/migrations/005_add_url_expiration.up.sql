-- Add expiration support to URLs table
ALTER TABLE urls ADD COLUMN expires_at TIMESTAMPTZ;

-- Create index for efficient expiration queries
CREATE INDEX IF NOT EXISTS idx_urls_expires_at ON urls (expires_at) WHERE expires_at IS NOT NULL;

-- Create index for non-expired URLs lookup
CREATE INDEX IF NOT EXISTS idx_urls_active ON urls (short_code) WHERE expires_at IS NULL OR expires_at > NOW();