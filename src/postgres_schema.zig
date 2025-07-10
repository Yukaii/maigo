const std = @import("std");
const postgres = @import("postgres.zig");

/// PostgreSQL schema management for Maigo URL shortener
pub fn createTables(db: *postgres.Database) !void {
    // Create users table first (referenced by other tables)
    const create_users_table =
        \\CREATE TABLE IF NOT EXISTS users (
        \\    id BIGSERIAL PRIMARY KEY,
        \\    username VARCHAR(255) UNIQUE NOT NULL,
        \\    email VARCHAR(255) UNIQUE NOT NULL,
        \\    password_hash VARCHAR(255) NOT NULL,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        \\);
    ;

    // Create OAuth clients table
    const create_oauth_clients_table =
        \\CREATE TABLE IF NOT EXISTS oauth_clients (
        \\    id VARCHAR(255) PRIMARY KEY,
        \\    secret VARCHAR(255) NOT NULL,
        \\    name VARCHAR(255) NOT NULL,
        \\    redirect_uri VARCHAR(1024) NOT NULL,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        \\);
    ;

    // Create authorization codes table
    const create_authorization_codes_table =
        \\CREATE TABLE IF NOT EXISTS authorization_codes (
        \\    code VARCHAR(255) PRIMARY KEY,
        \\    client_id VARCHAR(255) NOT NULL,
        \\    user_id BIGINT NOT NULL,
        \\    redirect_uri VARCHAR(1024) NOT NULL,
        \\    expires_at TIMESTAMPTZ NOT NULL,
        \\    used BOOLEAN DEFAULT FALSE,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        \\    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
        \\    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        \\);
    ;

    // Create access tokens table
    const create_access_tokens_table =
        \\CREATE TABLE IF NOT EXISTS access_tokens (
        \\    token VARCHAR(255) PRIMARY KEY,
        \\    refresh_token VARCHAR(255),
        \\    client_id VARCHAR(255) NOT NULL,
        \\    user_id BIGINT NOT NULL,
        \\    scope VARCHAR(512) NOT NULL,
        \\    expires_at TIMESTAMPTZ NOT NULL,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        \\    FOREIGN KEY (client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE,
        \\    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        \\);
    ;

    // Create URLs table
    const create_urls_table =
        \\CREATE TABLE IF NOT EXISTS urls (
        \\    id BIGSERIAL PRIMARY KEY,
        \\    short_code VARCHAR(255) UNIQUE NOT NULL,
        \\    target_url TEXT NOT NULL,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        \\    hits BIGINT DEFAULT 0,
        \\    user_id BIGINT,
        \\    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        \\);
    ;

    // Create domains table (for custom domain support)
    const create_domains_table =
        \\CREATE TABLE IF NOT EXISTS domains (
        \\    id BIGSERIAL PRIMARY KEY,
        \\    domain VARCHAR(255) UNIQUE NOT NULL,
        \\    user_id BIGINT NOT NULL,
        \\    ssl_cert TEXT,
        \\    ssl_key TEXT,
        \\    verified BOOLEAN DEFAULT FALSE,
        \\    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        \\    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        \\);
    ;

    // Execute table creation in order (respecting foreign key dependencies)
    try execSQL(db, create_users_table);
    try execSQL(db, create_oauth_clients_table);
    try execSQL(db, create_authorization_codes_table);
    try execSQL(db, create_access_tokens_table);
    try execSQL(db, create_urls_table);
    try execSQL(db, create_domains_table);

    // Create indices for better performance
    try createIndices(db);
}

fn createIndices(db: *postgres.Database) !void {
    const indices = [_][]const u8{
        "CREATE INDEX IF NOT EXISTS idx_urls_short_code ON urls(short_code);",
        "CREATE INDEX IF NOT EXISTS idx_urls_user_id ON urls(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_urls_created_at ON urls(created_at);",
        "CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id);",
        "CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);",
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);",
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);",
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);",
        "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);",
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);",
    };

    for (indices) |index_sql| {
        try execSQL(db, index_sql);
    }
}

fn execSQL(db: *postgres.Database, sql: []const u8) !void {
    const conn = db.pool.acquire() catch |err| {
        std.debug.print("Failed to acquire connection for SQL: {}\n", .{err});
        return postgres.PostgresError.ConnectionFailed;
    };
    defer db.pool.release(conn);

    _ = conn.query(sql, .{}) catch |err| {
        std.debug.print("Failed to execute SQL: {s}\nError: {}\n", .{ sql, err });
        return postgres.PostgresError.QueryFailed;
    };
}

test "postgres schema creation" {
    const allocator = std.testing.allocator;

    // This test requires a running PostgreSQL instance
    const config = postgres.DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = postgres.Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL schema test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    try createTables(&db);
}