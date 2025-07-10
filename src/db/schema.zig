const std = @import("std");
const core = @import("core.zig");

/// Database schema management
pub fn createTables(db: *core.Database) !void {
    const create_urls_table =
        \\CREATE TABLE IF NOT EXISTS urls (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    short_code TEXT UNIQUE NOT NULL,
        \\    target_url TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    hits INTEGER DEFAULT 0,
        \\    user_id INTEGER,
        \\    FOREIGN KEY (user_id) REFERENCES users (id)
        \\);
    ;

    const create_users_table =
        \\CREATE TABLE IF NOT EXISTS users (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    username TEXT UNIQUE NOT NULL,
        \\    email TEXT UNIQUE NOT NULL,
        \\    password_hash TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    ;

    const create_oauth_clients_table =
        \\CREATE TABLE IF NOT EXISTS oauth_clients (
        \\    id TEXT PRIMARY KEY,
        \\    secret TEXT NOT NULL,
        \\    name TEXT NOT NULL,
        \\    redirect_uri TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    ;

    const create_authorization_codes_table =
        \\CREATE TABLE IF NOT EXISTS authorization_codes (
        \\    code TEXT PRIMARY KEY,
        \\    client_id TEXT NOT NULL,
        \\    user_id INTEGER NOT NULL,
        \\    redirect_uri TEXT NOT NULL,
        \\    expires_at INTEGER NOT NULL,
        \\    used BOOLEAN DEFAULT FALSE,
        \\    created_at INTEGER NOT NULL,
        \\    FOREIGN KEY (client_id) REFERENCES oauth_clients (id),
        \\    FOREIGN KEY (user_id) REFERENCES users (id)
        \\);
    ;

    const create_access_tokens_table =
        \\CREATE TABLE IF NOT EXISTS access_tokens (
        \\    token TEXT PRIMARY KEY,
        \\    refresh_token TEXT,
        \\    client_id TEXT NOT NULL,
        \\    user_id INTEGER NOT NULL,
        \\    scope TEXT NOT NULL,
        \\    expires_at INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    FOREIGN KEY (client_id) REFERENCES oauth_clients (id),
        \\    FOREIGN KEY (user_id) REFERENCES users (id)
        \\);
    ;

    try db.exec(create_users_table);
    try db.exec(create_oauth_clients_table);
    try db.exec(create_authorization_codes_table);
    try db.exec(create_access_tokens_table);
    try db.exec(create_urls_table);
}