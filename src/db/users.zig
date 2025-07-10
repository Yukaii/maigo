const std = @import("std");
const core = @import("core.zig");
const models = @import("models.zig");

pub const UserRepository = struct {
    db: *core.Database,

    pub fn init(db: *core.Database) UserRepository {
        return UserRepository{ .db = db };
    }

    pub fn insert(self: *UserRepository, username: []const u8, email: []const u8, password_hash: []const u8) !u64 {
        const sql = "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, username);
        try stmt.bindText(2, email);
        try stmt.bindText(3, password_hash);
        stmt.bindInt64(4, std.time.timestamp());

        _ = try stmt.step();
        return stmt.getLastInsertId(self.db);
    }

    pub fn getByUsername(self: *UserRepository, username: []const u8) !?models.User {
        const sql = "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, username);

        const result = try stmt.step();
        if (result != core.c.SQLITE_ROW) {
            return null;
        }

        const id = @as(u64, @intCast(stmt.getInt64(0)));
        const username_copy = try stmt.getTextAlloc(1) orelse return core.DatabaseError.InvalidData;
        const email_copy = try stmt.getTextAlloc(2) orelse return core.DatabaseError.InvalidData;
        const password_hash_copy = try stmt.getTextAlloc(3) orelse return core.DatabaseError.InvalidData;
        const created_at = stmt.getInt64(4);

        return models.User{
            .id = id,
            .username = username_copy,
            .email = email_copy,
            .password_hash = password_hash_copy,
            .created_at = created_at,
        };
    }
};