const std = @import("std");
const core = @import("core.zig");
const models = @import("models.zig");

pub const OAuthClientRepository = struct {
    db: *core.Database,

    pub fn init(db: *core.Database) OAuthClientRepository {
        return OAuthClientRepository{ .db = db };
    }

    pub fn insert(self: *OAuthClientRepository, id: []const u8, secret: []const u8, name: []const u8, redirect_uri: []const u8) !void {
        const sql = "INSERT INTO oauth_clients (id, secret, name, redirect_uri, created_at) VALUES (?, ?, ?, ?, ?)";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, id);
        try stmt.bindText(2, secret);
        try stmt.bindText(3, name);
        try stmt.bindText(4, redirect_uri);
        stmt.bindInt64(5, std.time.timestamp());

        _ = try stmt.step();
    }

    pub fn getById(self: *OAuthClientRepository, id: []const u8) !?models.OAuthClient {
        const sql = "SELECT id, secret, name, redirect_uri, created_at FROM oauth_clients WHERE id = ?";
        
        var stmt = try core.Statement.prepare(self.db, sql);
        defer stmt.deinit();

        try stmt.bindText(1, id);

        const result = try stmt.step();
        if (result != core.c.SQLITE_ROW) {
            return null;
        }

        const id_copy = try stmt.getTextAlloc(0) orelse return core.DatabaseError.InvalidData;
        const secret_copy = try stmt.getTextAlloc(1) orelse return core.DatabaseError.InvalidData;
        const name_copy = try stmt.getTextAlloc(2) orelse return core.DatabaseError.InvalidData;
        const redirect_uri_copy = try stmt.getTextAlloc(3) orelse return core.DatabaseError.InvalidData;
        const created_at = stmt.getInt64(4);

        return models.OAuthClient{
            .id = id_copy,
            .secret = secret_copy,
            .name = name_copy,
            .redirect_uri = redirect_uri_copy,
            .created_at = created_at,
        };
    }
};