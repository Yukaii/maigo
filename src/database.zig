const std = @import("std");
const testing = std.testing;
const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const DatabaseError = error{
    OpenFailed,
    PrepareFailed,
    ExecFailed,
    StepFailed,
    NotFound,
    InvalidData,
};

pub const Url = struct {
    id: u64,
    short_code: []const u8,
    target_url: []const u8,
    created_at: i64,
    hits: u64,
    user_id: ?u64,
    
    pub fn deinit(self: *Url, allocator: std.mem.Allocator) void {
        allocator.free(self.short_code);
        allocator.free(self.target_url);
    }
};

pub const User = struct {
    id: u64,
    username: []const u8,
    email: []const u8,
    created_at: i64,
    
    pub fn deinit(self: *User, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.email);
    }
};

pub const Database = struct {
    db: ?*c.sqlite3,
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator, db_path: []const u8) !Database {
        var db: ?*c.sqlite3 = null;
        
        const db_path_cstr = try allocator.dupeZ(u8, db_path);
        defer allocator.free(db_path_cstr);
        
        const result = c.sqlite3_open(db_path_cstr, &db);
        if (result != c.SQLITE_OK) {
            std.debug.print("Failed to open database: {s}\n", .{c.sqlite3_errmsg(db)});
            if (db) |database| {
                _ = c.sqlite3_close(database);
            }
            return DatabaseError.OpenFailed;
        }
        
        var database = Database{
            .db = db,
            .allocator = allocator,
        };
        
        try database.createTables();
        
        return database;
    }
    
    pub fn deinit(self: *Database) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
        }
    }
    
    fn createTables(self: *Database) !void {
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
            \\    created_at INTEGER NOT NULL
            \\);
        ;
        
        const create_domains_table = 
            \\CREATE TABLE IF NOT EXISTS domains (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    domain TEXT UNIQUE NOT NULL,
            \\    user_id INTEGER NOT NULL,
            \\    ssl_cert TEXT,
            \\    ssl_key TEXT,
            \\    verified BOOLEAN DEFAULT FALSE,
            \\    created_at INTEGER NOT NULL,
            \\    FOREIGN KEY (user_id) REFERENCES users (id)
            \\);
        ;
        
        try self.exec(create_urls_table);
        try self.exec(create_users_table);
        try self.exec(create_domains_table);
        
        // Create indices for better performance
        try self.exec("CREATE INDEX IF NOT EXISTS idx_urls_short_code ON urls(short_code);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_urls_user_id ON urls(user_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);");
    }
    
    fn exec(self: *Database, sql: []const u8) !void {
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        const result = c.sqlite3_exec(self.db, sql_cstr, null, null, null);
        if (result != c.SQLITE_OK) {
            std.debug.print("SQL execution failed: {s}\n", .{c.sqlite3_errmsg(self.db)});
            return DatabaseError.ExecFailed;
        }
    }
    
    pub fn insertUrl(self: *Database, short_code: []const u8, target_url: []const u8, user_id: ?u64) !u64 {
        const sql = "INSERT INTO urls (short_code, target_url, created_at, user_id) VALUES (?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const short_code_cstr = try self.allocator.dupeZ(u8, short_code);
        defer self.allocator.free(short_code_cstr);
        
        const target_url_cstr = try self.allocator.dupeZ(u8, target_url);
        defer self.allocator.free(target_url_cstr);
        
        const now = std.time.timestamp();
        
        _ = c.sqlite3_bind_text(stmt, 1, short_code_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, target_url_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 3, now);
        
        if (user_id) |uid| {
            _ = c.sqlite3_bind_int64(stmt, 4, @intCast(uid));
        } else {
            _ = c.sqlite3_bind_null(stmt, 4);
        }
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
        
        return @intCast(c.sqlite3_last_insert_rowid(self.db));
    }
    
    pub fn getUrlByShortCode(self: *Database, short_code: []const u8) !?Url {
        const sql = "SELECT id, short_code, target_url, created_at, hits, user_id FROM urls WHERE short_code = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const short_code_cstr = try self.allocator.dupeZ(u8, short_code);
        defer self.allocator.free(short_code_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, short_code_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            const id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 0)));
            const code = std.mem.span(c.sqlite3_column_text(stmt, 1));
            const target = std.mem.span(c.sqlite3_column_text(stmt, 2));
            const created_at = c.sqlite3_column_int64(stmt, 3);
            const hits = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 4)));
            
            const user_id: ?u64 = if (c.sqlite3_column_type(stmt, 5) == c.SQLITE_NULL) 
                null 
            else 
                @as(u64, @intCast(c.sqlite3_column_int64(stmt, 5)));
            
            return Url{
                .id = id,
                .short_code = try self.allocator.dupe(u8, code),
                .target_url = try self.allocator.dupe(u8, target),
                .created_at = created_at,
                .hits = hits,
                .user_id = user_id,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn incrementHits(self: *Database, short_code: []const u8) !void {
        const sql = "UPDATE urls SET hits = hits + 1 WHERE short_code = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const short_code_cstr = try self.allocator.dupeZ(u8, short_code);
        defer self.allocator.free(short_code_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, short_code_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn shortCodeExists(self: *Database, short_code: []const u8) !bool {
        const sql = "SELECT 1 FROM urls WHERE short_code = ? LIMIT 1";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const short_code_cstr = try self.allocator.dupeZ(u8, short_code);
        defer self.allocator.free(short_code_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, short_code_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        return result == c.SQLITE_ROW;
    }
};

test "database basic operations" {
    const allocator = testing.allocator;
    
    // Use in-memory database for testing
    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();
    
    // Test inserting a URL
    const url_id = try db.insertUrl("test123", "https://example.com", null);
    try testing.expect(url_id > 0);
    
    // Test retrieving the URL
    var url = try db.getUrlByShortCode("test123");
    try testing.expect(url != null);
    
    if (url) |*u| {
        defer u.deinit(allocator);
        try testing.expectEqualStrings("test123", u.short_code);
        try testing.expectEqualStrings("https://example.com", u.target_url);
        try testing.expect(u.hits == 0);
        try testing.expect(u.user_id == null);
    }
    
    // Test incrementing hits
    try db.incrementHits("test123");
    
    var updated_url = try db.getUrlByShortCode("test123");
    try testing.expect(updated_url != null);
    
    if (updated_url) |*u| {
        defer u.deinit(allocator);
        try testing.expect(u.hits == 1);
    }
    
    // Test short code existence check
    try testing.expect(try db.shortCodeExists("test123"));
    try testing.expect(!try db.shortCodeExists("nonexistent"));
}