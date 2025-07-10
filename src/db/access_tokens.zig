const std = @import("std");
const core = @import("core.zig");
const models = @import("models.zig");

/// Access token operations - focused module to avoid corruption
pub const AccessTokenRepository = struct {
    db: *core.Database,

    pub fn init(db: *core.Database) AccessTokenRepository {
        return AccessTokenRepository{ .db = db };
    }

    pub fn insert(self: *AccessTokenRepository, token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8) !void {
        const sql = "INSERT INTO access_tokens (token, refresh_token, client_id, user_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, token);
        
        if (refresh_token) |rt| {
            try stmt.bindText(2, rt);
        } else {
            stmt.bindNull(2);
        }
        
        try stmt.bindText(3, client_id);
        stmt.bindInt64(4, @intCast(user_id));
        try stmt.bindText(5, scope);
        stmt.bindInt64(6, expires_at);
        stmt.bindInt64(7, std.time.timestamp());

        _ = try stmt.step();
    }

    pub fn getByToken(self: *AccessTokenRepository, token: []const u8) !?models.AccessToken {
        const sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at, created_at FROM access_tokens WHERE token = ?";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, token);

        const result = try stmt.step();
        if (result != core.c.SQLITE_ROW) {
            return null;
        }

        // Extract all data in careful order to avoid pointer invalidation
        const token_copy = try stmt.getTextAlloc(0) orelse return core.DatabaseError.InvalidData;
        const refresh_token_copy = try stmt.getTextAlloc(1); // Can be null
        const client_id_copy = try stmt.getTextAlloc(2) orelse return core.DatabaseError.InvalidData;
        const user_id = @as(u64, @intCast(stmt.getInt64(3)));
        const scope_copy = try stmt.getTextAlloc(4) orelse return core.DatabaseError.InvalidData;
        const expires_at = stmt.getInt64(5);
        const created_at = stmt.getInt64(6);

        return models.AccessToken{
            .token = token_copy,
            .refresh_token = refresh_token_copy,
            .client_id = client_id_copy,
            .user_id = user_id,
            .scope = scope_copy,
            .expires_at = expires_at,
            .created_at = created_at,
        };
    }

    pub fn getByRefreshToken(self: *AccessTokenRepository, refresh_token: []const u8) !?models.AccessToken {
        const sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at, created_at FROM access_tokens WHERE refresh_token = ?";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, refresh_token);

        const result = try stmt.step();
        if (result != core.c.SQLITE_ROW) {
            return null;
        }

        // Extract all data in careful order
        const token_copy = try stmt.getTextAlloc(0) orelse return core.DatabaseError.InvalidData;
        const refresh_token_copy = try stmt.getTextAlloc(1); // Can be null
        const client_id_copy = try stmt.getTextAlloc(2) orelse return core.DatabaseError.InvalidData;
        const user_id = @as(u64, @intCast(stmt.getInt64(3)));
        const scope_copy = try stmt.getTextAlloc(4) orelse return core.DatabaseError.InvalidData;
        const expires_at = stmt.getInt64(5);
        const created_at = stmt.getInt64(6);

        return models.AccessToken{
            .token = token_copy,
            .refresh_token = refresh_token_copy,
            .client_id = client_id_copy,
            .user_id = user_id,
            .scope = scope_copy,
            .expires_at = expires_at,
            .created_at = created_at,
        };
    }

    pub fn revoke(self: *AccessTokenRepository, token: []const u8) !void {
        const sql = "DELETE FROM access_tokens WHERE token = ?";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, token);
        _ = try stmt.step();
    }
};