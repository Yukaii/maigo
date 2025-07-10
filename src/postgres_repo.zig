const std = @import("std");
const pg = @import("pg");
const postgres = @import("postgres.zig");

// Import existing models for compatibility
const models = @import("db/models.zig");
pub const Url = models.Url;
pub const User = models.User;
pub const OAuthClient = models.OAuthClient;
pub const AuthorizationCode = models.AuthorizationCode;
pub const AccessToken = models.AccessToken;

pub const UserRepository = struct {
    db: *postgres.Database,

    pub fn init(db: *postgres.Database) UserRepository {
        return UserRepository{ .db = db };
    }

    pub fn insert(self: *UserRepository, username: []const u8, email: []const u8, password_hash: []const u8) !u64 {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id";
        const result = conn.query(sql, .{ username, email, password_hash }) catch |err| {
            std.debug.print("Failed to insert user: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        if (try result.next()) |row| {
            return row.get(u64, 0);
        } else {
            return postgres.PostgresError.QueryFailed;
        }
    }

    pub fn getByUsername(self: *UserRepository, username: []const u8) !?User {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "SELECT id, username, email, password_hash, EXTRACT(EPOCH FROM created_at) FROM users WHERE username = $1";
        const result = conn.query(sql, .{username}) catch |err| {
            std.debug.print("Failed to query user: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        if (try result.next()) |row| {
            return User{
                .id = row.get(u64, 0),
                .username = try self.db.allocator.dupe(u8, row.get([]const u8, 1)),
                .email = try self.db.allocator.dupe(u8, row.get([]const u8, 2)),
                .password_hash = try self.db.allocator.dupe(u8, row.get([]const u8, 3)),
                .created_at = @intFromFloat(row.get(f64, 4)),
            };
        } else {
            return null;
        }
    }
};

pub const OAuthClientRepository = struct {
    db: *postgres.Database,

    pub fn init(db: *postgres.Database) OAuthClientRepository {
        return OAuthClientRepository{ .db = db };
    }

    pub fn insert(self: *OAuthClientRepository, id: []const u8, secret: []const u8, name: []const u8, redirect_uri: []const u8) !void {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "INSERT INTO oauth_clients (id, secret, name, redirect_uri) VALUES ($1, $2, $3, $4)";
        _ = conn.query(sql, .{ id, secret, name, redirect_uri }) catch |err| {
            std.debug.print("Failed to insert OAuth client: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
    }

    pub fn getById(self: *OAuthClientRepository, id: []const u8) !?OAuthClient {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "SELECT id, secret, name, redirect_uri, EXTRACT(EPOCH FROM created_at) FROM oauth_clients WHERE id = $1";
        const result = conn.query(sql, .{id}) catch |err| {
            std.debug.print("Failed to query OAuth client: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        if (try result.next()) |row| {
            return OAuthClient{
                .id = try self.db.allocator.dupe(u8, row.get([]const u8, 0)),
                .secret = try self.db.allocator.dupe(u8, row.get([]const u8, 1)),
                .name = try self.db.allocator.dupe(u8, row.get([]const u8, 2)),
                .redirect_uri = try self.db.allocator.dupe(u8, row.get([]const u8, 3)),
                .created_at = @intFromFloat(row.get(f64, 4)),
            };
        } else {
            return null;
        }
    }
};

pub const UrlRepository = struct {
    db: *postgres.Database,

    pub fn init(db: *postgres.Database) UrlRepository {
        return UrlRepository{ .db = db };
    }

    pub fn insert(self: *UrlRepository, short_code: []const u8, target_url: []const u8, user_id: ?u64) !u64 {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "INSERT INTO urls (short_code, target_url, user_id) VALUES ($1, $2, $3) RETURNING id";
        const result = conn.query(sql, .{ short_code, target_url, user_id }) catch |err| {
            std.debug.print("Failed to insert URL: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        if (try result.next()) |row| {
            return row.get(u64, 0);
        } else {
            return postgres.PostgresError.QueryFailed;
        }
    }

    pub fn getByShortCode(self: *UrlRepository, short_code: []const u8) !?Url {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "SELECT id, short_code, target_url, EXTRACT(EPOCH FROM created_at), hits, user_id FROM urls WHERE short_code = $1";
        const result = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to query URL: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        if (try result.next()) |row| {
            return Url{
                .id = row.get(u64, 0),
                .short_code = try self.db.allocator.dupe(u8, row.get([]const u8, 1)),
                .target_url = try self.db.allocator.dupe(u8, row.get([]const u8, 2)),
                .created_at = @intFromFloat(row.get(f64, 3)),
                .hits = row.get(u64, 4),
                .user_id = row.get(?u64, 5),
            };
        } else {
            return null;
        }
    }

    pub fn incrementHits(self: *UrlRepository, short_code: []const u8) !void {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "UPDATE urls SET hits = hits + 1 WHERE short_code = $1";
        _ = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to increment hits: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
    }

    pub fn shortCodeExists(self: *UrlRepository, short_code: []const u8) !bool {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "SELECT 1 FROM urls WHERE short_code = $1 LIMIT 1";
        const result = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to check short code existence: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };

        return try result.next() != null;
    }
};

test "postgres repository basic operations" {
    const allocator = std.testing.allocator;

    // This test requires a running PostgreSQL instance
    const config = postgres.DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = postgres.Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL repository test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    var user_repo = UserRepository.init(&db);
    var oauth_repo = OAuthClientRepository.init(&db);
    var url_repo = UrlRepository.init(&db);

    // Test user operations
    const user_id = user_repo.insert("testuser", "test@example.com", "hashedpassword") catch |err| {
        std.debug.print("Failed to insert user: {}\n", .{err});
        return;
    };

    var user = try user_repo.getByUsername("testuser");
    defer if (user) |*u| u.deinit(allocator);

    if (user) |u| {
        try std.testing.expectEqualStrings("testuser", u.username);
        try std.testing.expectEqualStrings("test@example.com", u.email);
        try std.testing.expect(u.id == user_id);
    }

    // Test OAuth client operations
    oauth_repo.insert("test-client", "test-secret", "Test Client", "http://localhost:3000/callback") catch |err| {
        std.debug.print("Failed to insert OAuth client: {}\n", .{err});
        return;
    };

    var oauth_client = try oauth_repo.getById("test-client");
    defer if (oauth_client) |*c| c.deinit(allocator);

    if (oauth_client) |c| {
        try std.testing.expectEqualStrings("test-client", c.id);
        try std.testing.expectEqualStrings("test-secret", c.secret);
    }

    // Test URL operations
    const url_id = url_repo.insert("test123", "https://example.com", user_id) catch |err| {
        std.debug.print("Failed to insert URL: {}\n", .{err});
        return;
    };

    var url = try url_repo.getByShortCode("test123");
    defer if (url) |*u| u.deinit(allocator);

    if (url) |u| {
        try std.testing.expectEqualStrings("test123", u.short_code);
        try std.testing.expectEqualStrings("https://example.com", u.target_url);
        try std.testing.expect(u.id == url_id);
        try std.testing.expect(u.hits == 0);
        try std.testing.expect(u.user_id == user_id);
    }

    // Test hit increment
    try url_repo.incrementHits("test123");
    var updated_url = try url_repo.getByShortCode("test123");
    defer if (updated_url) |*u| u.deinit(allocator);

    if (updated_url) |u| {
        try std.testing.expect(u.hits == 1);
    }

    // Test short code existence
    try std.testing.expect(try url_repo.shortCodeExists("test123"));
    try std.testing.expect(!try url_repo.shortCodeExists("nonexistent"));
}