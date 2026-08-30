-- A user may hold one refresh session per device or client.
DROP INDEX IF EXISTS idx_sessions_user_id;
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
