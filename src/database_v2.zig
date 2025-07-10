const std = @import("std");

// Import modular components
const core = @import("db/core.zig");
const schema = @import("db/schema.zig");
const models = @import("db/models.zig");
const access_tokens = @import("db/access_tokens.zig");
const users = @import("db/users.zig");
const oauth_clients = @import("db/oauth_clients.zig");

// Re-export types for compatibility
pub const DatabaseError = core.DatabaseError;
pub const Url = models.Url;
pub const User = models.User;
pub const OAuthClient = models.OAuthClient;
pub const AuthorizationCode = models.AuthorizationCode;
pub const AccessToken = models.AccessToken;

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

/// Main database interface - composing repositories
pub const Database = struct {
    core_db: core.Database,
    access_tokens: access_tokens.AccessTokenRepository,
    users: users.UserRepository,
    oauth_clients: oauth_clients.OAuthClientRepository,

    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Database {
        var core_db = try core.Database.init(allocator, db_path);
        
        // Create schema
        try schema.createTables(&core_db);
        
        // Initialize repositories
        var db = Database{
            .core_db = core_db,
            .access_tokens = access_tokens.AccessTokenRepository.init(&core_db),
            .users = users.UserRepository.init(&core_db),
            .oauth_clients = oauth_clients.OAuthClientRepository.init(&core_db),
        };
        
        // Insert CLI client fixture (without printing debug message)
        try db.insertCliClientFixture();
        
        return db;
    }

    pub fn deinit(self: *Database) void {
        self.core_db.deinit();
    }

    fn insertCliClientFixture(self: *Database) !void {
        // Check if CLI client already exists
        const existing = try self.oauth_clients.getById(CLI_CLIENT_ID);
        if (existing != null) {
            if (existing) |client| {
                var mutable_client = client;
                mutable_client.deinit(self.core_db.allocator);
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

    // Access token operations
    pub fn insertAccessToken(self: *Database, token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8) !void {
        return try self.access_tokens.insert(token, client_id, user_id, scope, expires_at, refresh_token);
    }

    pub fn getAccessToken(self: *Database, token: []const u8) !?AccessToken {
        return try self.access_tokens.getByToken(token);
    }

    pub fn getAccessTokenByRefresh(self: *Database, refresh_token: []const u8) !?AccessToken {
        return try self.access_tokens.getByRefreshToken(refresh_token);
    }

    pub fn revokeAccessToken(self: *Database, token: []const u8) !void {
        return try self.access_tokens.revoke(token);
    }
};