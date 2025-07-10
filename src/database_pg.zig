const std = @import("std");
const postgres = @import("postgres.zig");
const postgres_schema = @import("postgres_schema.zig");
const postgres_repo = @import("postgres_repo.zig");

// Re-export models for compatibility
pub const Url = postgres_repo.Url;
pub const User = postgres_repo.User;
pub const OAuthClient = postgres_repo.OAuthClient;
pub const AuthorizationCode = postgres_repo.AuthorizationCode;
pub const AccessToken = postgres_repo.AccessToken;

// CLI Client fixture constants
const CLI_CLIENT_ID = "maigo-cli";
const CLI_CLIENT_SECRET = "cli-secret-fixed-deterministic-value-for-embedded-client";
const CLI_CLIENT_NAME = "Maigo CLI";
const CLI_CLIENT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

pub const CliClientCredentials = struct {
    client_id: []const u8,
    client_secret: []const u8,
    name: []const u8,
    redirect_uri: []const u8,
};

pub fn getCliClientCredentials() CliClientCredentials {
    return CliClientCredentials{
        .client_id = CLI_CLIENT_ID,
        .client_secret = CLI_CLIENT_SECRET,
        .name = CLI_CLIENT_NAME,
        .redirect_uri = CLI_CLIENT_REDIRECT_URI,
    };
}

/// PostgreSQL-backed database implementation
pub const Database = struct {
    postgres_db: postgres.Database,
    users: postgres_repo.UserRepository,
    oauth_clients: postgres_repo.OAuthClientRepository,
    urls: postgres_repo.UrlRepository,

    pub fn init(allocator: std.mem.Allocator, config: postgres.DatabaseConfig) !Database {
        var postgres_db = try postgres.Database.init(allocator, config);
        
        // Create schema
        try postgres_schema.createTables(&postgres_db);
        
        // Initialize repositories
        var db = Database{
            .postgres_db = postgres_db,
            .users = postgres_repo.UserRepository.init(&postgres_db),
            .oauth_clients = postgres_repo.OAuthClientRepository.init(&postgres_db),
            .urls = postgres_repo.UrlRepository.init(&postgres_db),
        };
        
        // Insert CLI client fixture
        try db.insertCliClientFixture();
        
        return db;
    }

    pub fn deinit(self: *Database) void {
        self.postgres_db.deinit();
    }

    fn insertCliClientFixture(self: *Database) !void {
        // Check if CLI client already exists
        const existing = try self.oauth_clients.getById(CLI_CLIENT_ID);
        if (existing != null) {
            if (existing) |client| {
                var mutable_client = client;
                mutable_client.deinit(self.postgres_db.allocator);
            }
            return;
        }

        // Insert CLI client
        try self.oauth_clients.insert(CLI_CLIENT_ID, CLI_CLIENT_SECRET, CLI_CLIENT_NAME, CLI_CLIENT_REDIRECT_URI);
    }

    // User operations
    pub fn insertUser(self: *Database, username: []const u8, email: []const u8, password_hash: []const u8) !u64 {
        return try self.users.insert(username, email, password_hash);
    }

    pub fn getUserByUsername(self: *Database, username: []const u8) !?User {
        return try self.users.getByUsername(username);
    }

    // OAuth client operations
    pub fn insertOAuthClient(self: *Database, id: []const u8, secret: []const u8, name: []const u8, redirect_uri: []const u8) !void {
        return try self.oauth_clients.insert(id, secret, name, redirect_uri);
    }

    pub fn getOAuthClient(self: *Database, id: []const u8) !?OAuthClient {
        return try self.oauth_clients.getById(id);
    }

    // URL operations
    pub fn insertUrl(self: *Database, short_code: []const u8, target_url: []const u8, user_id: ?u64) !u64 {
        return try self.urls.insert(short_code, target_url, user_id);
    }

    pub fn getUrlByShortCode(self: *Database, short_code: []const u8) !?Url {
        return try self.urls.getByShortCode(short_code);
    }

    pub fn incrementHits(self: *Database, short_code: []const u8) !void {
        return try self.urls.incrementHits(short_code);
    }

    pub fn shortCodeExists(self: *Database, short_code: []const u8) !bool {
        return try self.urls.shortCodeExists(short_code);
    }

    // TODO: Implement remaining methods as needed
    // For now, these are stubs that will be implemented incrementally

    pub fn insertAuthorizationCode(self: *Database, code: []const u8, client_id: []const u8, user_id: u64, redirect_uri: []const u8, expires_at: i64) !void {
        _ = self;
        _ = code;
        _ = client_id;
        _ = user_id;
        _ = redirect_uri;
        _ = expires_at;
        return postgres.PostgresError.QueryFailed; // TODO: Implement
    }

    pub fn getAuthorizationCode(self: *Database, code: []const u8) !?AuthorizationCode {
        _ = self;
        _ = code;
        return null; // TODO: Implement
    }

    pub fn markAuthorizationCodeUsed(self: *Database, code: []const u8) !void {
        _ = self;
        _ = code;
        return postgres.PostgresError.QueryFailed; // TODO: Implement
    }

    pub fn insertAccessToken(self: *Database, token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8) !void {
        _ = self;
        _ = token;
        _ = client_id;
        _ = user_id;
        _ = scope;
        _ = expires_at;
        _ = refresh_token;
        return postgres.PostgresError.QueryFailed; // TODO: Implement
    }

    pub fn getAccessToken(self: *Database, token: []const u8) !?AccessToken {
        _ = self;
        _ = token;
        return null; // TODO: Implement
    }

    pub fn getAccessTokenByRefresh(self: *Database, refresh_token: []const u8) !?AccessToken {
        _ = self;
        _ = refresh_token;
        return null; // TODO: Implement
    }

    pub fn revokeAccessToken(self: *Database, token: []const u8) !void {
        _ = self;
        _ = token;
        return postgres.PostgresError.QueryFailed; // TODO: Implement
    }
};

test "postgres database basic operations" {
    const allocator = std.testing.allocator;

    // This test requires a running PostgreSQL instance
    const config = postgres.DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL database test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    // Test inserting a URL
    const url_id = try db.insertUrl("test123", "https://example.com", null);
    try std.testing.expect(url_id > 0);

    // Test retrieving the URL
    var url = try db.getUrlByShortCode("test123");
    try std.testing.expect(url != null);

    if (url) |*u| {
        defer u.deinit(allocator);
        try std.testing.expectEqualStrings("test123", u.short_code);
        try std.testing.expectEqualStrings("https://example.com", u.target_url);
        try std.testing.expect(u.hits == 0);
        try std.testing.expect(u.user_id == null);
    }

    // Test incrementing hits
    try db.incrementHits("test123");

    var updated_url = try db.getUrlByShortCode("test123");
    try std.testing.expect(updated_url != null);

    if (updated_url) |*u| {
        defer u.deinit(allocator);
        try std.testing.expect(u.hits == 1);
    }

    // Test short code existence check
    try std.testing.expect(try db.shortCodeExists("test123"));
    try std.testing.expect(!try db.shortCodeExists("nonexistent"));
}

test "postgres database user operations" {
    const allocator = std.testing.allocator;

    const config = postgres.DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL user test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    // Test inserting a user
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword123");
    try std.testing.expect(user_id > 0);

    // Test retrieving the user
    var user = try db.getUserByUsername("testuser");
    try std.testing.expect(user != null);

    if (user) |*u| {
        defer u.deinit(allocator);
        try std.testing.expectEqualStrings("testuser", u.username);
        try std.testing.expectEqualStrings("test@example.com", u.email);
        try std.testing.expectEqualStrings("hashedpassword123", u.password_hash);
        try std.testing.expect(u.id == user_id);
        try std.testing.expect(u.created_at > 0);
    }

    // Test retrieving non-existent user
    const nonexistent_user = try db.getUserByUsername("nonexistent");
    try std.testing.expect(nonexistent_user == null);
}

test "postgres database oauth client operations" {
    const allocator = std.testing.allocator;

    const config = postgres.DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL OAuth test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    // Test CLI client fixture is automatically inserted
    const cli_client = try db.getOAuthClient("maigo-cli");
    try std.testing.expect(cli_client != null);

    if (cli_client) |client| {
        try std.testing.expectEqualStrings("maigo-cli", client.id);
        try std.testing.expectEqualStrings("cli-secret-fixed-deterministic-value-for-embedded-client", client.secret);
        try std.testing.expectEqualStrings("Maigo CLI", client.name);
        try std.testing.expectEqualStrings("urn:ietf:wg:oauth:2.0:oob", client.redirect_uri);
        
        var mutable_client = client;
        mutable_client.deinit(allocator);
    }

    // Test inserting a custom OAuth client
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    const custom_client = try db.getOAuthClient("test-client");
    try std.testing.expect(custom_client != null);

    if (custom_client) |client| {
        try std.testing.expectEqualStrings("test-client", client.id);
        try std.testing.expectEqualStrings("test-secret", client.secret);
        try std.testing.expectEqualStrings("Test Client", client.name);
        try std.testing.expectEqualStrings("http://localhost:3000/callback", client.redirect_uri);
        
        var mutable_client = client;
        mutable_client.deinit(allocator);
    }

    // Test retrieving non-existent client
    const nonexistent_client = try db.getOAuthClient("nonexistent");
    try std.testing.expect(nonexistent_client == null);
}