-- Drop tables in reverse order of creation to respect foreign key constraints
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS urls;
DROP TABLE IF EXISTS access_tokens;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS oauth_clients;
DROP TABLE IF EXISTS users;
