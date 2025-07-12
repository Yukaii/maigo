-- Insert CLI OAuth client with hardcoded values for the Maigo CLI application
-- This client uses PKCE for security and doesn't require a client secret for public clients
INSERT INTO oauth_clients (id, secret, name, redirect_uri, created_at) 
VALUES (
    'maigo-cli',
    'cli-client-secret-not-used-with-pkce', 
    'Maigo CLI Application',
    'http://localhost:8000/callback',
    NOW()
) ON CONFLICT (id) DO UPDATE SET
    secret = EXCLUDED.secret,
    name = EXCLUDED.name,
    redirect_uri = EXCLUDED.redirect_uri;
