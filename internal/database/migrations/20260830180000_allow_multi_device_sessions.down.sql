-- Recreating the unique index may fail if multiple sessions exist for a user.
-- Back up and reconcile session rows before manually rolling back this change.
DROP INDEX IF EXISTS idx_sessions_expires_at;
DROP INDEX IF EXISTS idx_sessions_user_id;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
