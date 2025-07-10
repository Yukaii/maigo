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

        // Cleanup any existing user with the same username or email before insert
        var cleanup_result = conn.query("DELETE FROM users WHERE username = $1 OR email = $2", .{username, email}) catch |err| {
            std.debug.print("Failed to cleanup user before insert: {}\n", .{err});
            if (conn.err) |pge| {
                std.debug.print("PG error code: {s}\n", .{pge.code});
                std.debug.print("PG error message: {s}\n", .{pge.message});
                if (pge.constraint) |c| std.debug.print("PG error constraint: {s}\n", .{c});
            }
            return postgres.PostgresError.QueryFailed;
        };
    try cleanup_result.drain();
    cleanup_result.deinit();

        const sql = "INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id";
        var result = conn.query(sql, .{ username, email, password_hash }) catch |err| {
            std.debug.print("Failed to insert user: {}\n", .{err});
            // Print full Postgres error details if available
            if (conn.err) |pge| {
                std.debug.print("PG error code: {s}\n", .{pge.code});
                std.debug.print("PG error message: {s}\n", .{pge.message});
                if (pge.constraint) |c| std.debug.print("PG error constraint: {s}\n", .{c});
            }
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

        if (try result.next()) |row| {
            return @intCast(row.get(i64, 0));
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
        var result = conn.query(sql, .{username}) catch |err| {
            std.debug.print("Failed to query user: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

        if (try result.next()) |row| {
            return User{
                .id = @intCast(row.get(i64, 0)),
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
        var result = conn.query(sql, .{id}) catch |err| {
            std.debug.print("Failed to query OAuth client: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

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

        // Cleanup any existing URL with the same short_code or target_url before insert
        var cleanup_result = conn.query("DELETE FROM urls WHERE short_code = $1 OR target_url = $2", .{short_code, target_url}) catch |err| {
            std.debug.print("Failed to cleanup URL before insert: {}\n", .{err});
            if (conn.err) |pge| {
                std.debug.print("PG error code: {s}\n", .{pge.code});
                std.debug.print("PG error message: {s}\n", .{pge.message});
                if (pge.constraint) |c| std.debug.print("PG error constraint: {s}\n", .{c});
            }
            return postgres.PostgresError.QueryFailed;
        };
        try cleanup_result.drain();
        cleanup_result.deinit();

        const sql = "INSERT INTO urls (short_code, target_url, user_id) VALUES ($1, $2, $3) RETURNING id";
        var result = conn.query(sql, .{ short_code, target_url, user_id }) catch |err| {
            std.debug.print("Failed to insert URL: {}\n", .{err});
            if (conn.err) |pge| {
                std.debug.print("PG error code: {s}\n", .{pge.code});
                std.debug.print("PG error message: {s}\n", .{pge.message});
                if (pge.constraint) |c| std.debug.print("PG error constraint: {s}\n", .{c});
            }
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

        if (try result.next()) |row| {
            return @intCast(row.get(i64, 0));
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
        var result = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to query URL: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

        if (try result.next()) |row| {
            return Url{
                .id = @intCast(row.get(i64, 0)),
                .short_code = try self.db.allocator.dupe(u8, row.get([]const u8, 1)),
                .target_url = try self.db.allocator.dupe(u8, row.get([]const u8, 2)),
                .created_at = @intFromFloat(row.get(f64, 3)),
                .hits = @intCast(row.get(i64, 4)),
                .user_id = if (row.get(?i64, 5)) |id| @as(u64, @intCast(id)) else null,
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
        var result = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to increment hits: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
        try result.drain();
        result.deinit();
    }

    pub fn shortCodeExists(self: *UrlRepository, short_code: []const u8) !bool {
        const conn = self.db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return postgres.PostgresError.ConnectionFailed;
        };
        defer self.db.pool.release(conn);

        const sql = "SELECT 1 FROM urls WHERE short_code = $1 LIMIT 1";
        var result = conn.query(sql, .{short_code}) catch |err| {
            std.debug.print("Failed to check short code existence: {}\n", .{err});
            return postgres.PostgresError.QueryFailed;
        };
        defer result.deinit();

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


    // Clean up test user if exists (by username and email)
    {
        const conn = db.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection for cleanup: {}\n", .{err});
            return;
        };
        defer db.pool.release(conn);
        _ = conn.query("DELETE FROM users WHERE username = $1 OR email = $2", .{"testuser", "test@example.com"}) catch null;
    }

    // Test user operations
    const user_id = user_repo.insert("testuser", "test@example.com", "hashedpassword") catch |err| {
        std.debug.print("Failed to insert user: {any}\n", .{err});
        // Print full Postgres error details if available
        if (db.pool.acquire() catch null) |conn| {
            defer db.pool.release(conn);
            if (@hasField(@TypeOf(conn), "err") and conn.err) |pge| {
                std.debug.print("PG error code: {s}\n", .{pge.code});
                std.debug.print("PG error message: {s}\n", .{pge.message});
                if (pge.constraint) |c| std.debug.print("PG error constraint: {s}\n", .{c});
            }
        }
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