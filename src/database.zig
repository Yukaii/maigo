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
            \\    client_id TEXT NOT NULL,
            \\    user_id INTEGER NOT NULL,
            \\    scope TEXT NOT NULL,
            \\    expires_at INTEGER NOT NULL,
            \\    refresh_token TEXT,
            \\    created_at INTEGER NOT NULL,
            \\    FOREIGN KEY (client_id) REFERENCES oauth_clients (id),
            \\    FOREIGN KEY (user_id) REFERENCES users (id)
            \\);
        ;
        
        try self.exec(create_urls_table);
        try self.exec(create_users_table);
        try self.exec(create_domains_table);
        try self.exec(create_oauth_clients_table);
        try self.exec(create_authorization_codes_table);
        try self.exec(create_access_tokens_table);
        
        // Create indices for better performance
        try self.exec("CREATE INDEX IF NOT EXISTS idx_urls_short_code ON urls(short_code);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_urls_user_id ON urls(user_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_domains_user_id ON domains(user_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_authorization_codes_client_id ON authorization_codes(client_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_authorization_codes_user_id ON authorization_codes(user_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_access_tokens_client_id ON access_tokens(client_id);");
        try self.exec("CREATE INDEX IF NOT EXISTS idx_access_tokens_user_id ON access_tokens(user_id);");
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
    
    // OAuth Client operations
    pub fn insertOAuthClient(self: *Database, client_id: []const u8, secret: []const u8, name: []const u8, redirect_uri: []const u8) !void {
        const sql = "INSERT INTO oauth_clients (id, secret, name, redirect_uri, created_at) VALUES (?, ?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const client_id_cstr = try self.allocator.dupeZ(u8, client_id);
        defer self.allocator.free(client_id_cstr);
        
        const secret_cstr = try self.allocator.dupeZ(u8, secret);
        defer self.allocator.free(secret_cstr);
        
        const name_cstr = try self.allocator.dupeZ(u8, name);
        defer self.allocator.free(name_cstr);
        
        const redirect_uri_cstr = try self.allocator.dupeZ(u8, redirect_uri);
        defer self.allocator.free(redirect_uri_cstr);
        
        const now = std.time.timestamp();
        
        _ = c.sqlite3_bind_text(stmt, 1, client_id_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, secret_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 3, name_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 4, redirect_uri_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 5, now);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn getOAuthClient(self: *Database, client_id: []const u8) !?struct { id: []const u8, secret: []const u8, name: []const u8, redirect_uri: []const u8 } {
        const sql = "SELECT id, secret, name, redirect_uri FROM oauth_clients WHERE id = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const client_id_cstr = try self.allocator.dupeZ(u8, client_id);
        defer self.allocator.free(client_id_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, client_id_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            const id = std.mem.span(c.sqlite3_column_text(stmt, 0));
            const secret = std.mem.span(c.sqlite3_column_text(stmt, 1));
            const name = std.mem.span(c.sqlite3_column_text(stmt, 2));
            const redirect_uri = std.mem.span(c.sqlite3_column_text(stmt, 3));
            
            return .{
                .id = try self.allocator.dupe(u8, id),
                .secret = try self.allocator.dupe(u8, secret),
                .name = try self.allocator.dupe(u8, name),
                .redirect_uri = try self.allocator.dupe(u8, redirect_uri),
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }
    
    // Authorization Code operations
    pub fn insertAuthorizationCode(self: *Database, code: []const u8, client_id: []const u8, user_id: u64, redirect_uri: []const u8, expires_at: i64) !void {
        const sql = "INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const code_cstr = try self.allocator.dupeZ(u8, code);
        defer self.allocator.free(code_cstr);
        
        const client_id_cstr = try self.allocator.dupeZ(u8, client_id);
        defer self.allocator.free(client_id_cstr);
        
        const redirect_uri_cstr = try self.allocator.dupeZ(u8, redirect_uri);
        defer self.allocator.free(redirect_uri_cstr);
        
        const now = std.time.timestamp();
        
        _ = c.sqlite3_bind_text(stmt, 1, code_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, client_id_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 3, @intCast(user_id));
        _ = c.sqlite3_bind_text(stmt, 4, redirect_uri_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 5, expires_at);
        _ = c.sqlite3_bind_int64(stmt, 6, now);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn getAuthorizationCode(self: *Database, code: []const u8) !?struct { code: []const u8, client_id: []const u8, user_id: u64, redirect_uri: []const u8, expires_at: i64, used: bool } {
        const sql = "SELECT code, client_id, user_id, redirect_uri, expires_at, used FROM authorization_codes WHERE code = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const code_cstr = try self.allocator.dupeZ(u8, code);
        defer self.allocator.free(code_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, code_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            const auth_code = std.mem.span(c.sqlite3_column_text(stmt, 0));
            const client_id = std.mem.span(c.sqlite3_column_text(stmt, 1));
            const user_id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 2)));
            const redirect_uri = std.mem.span(c.sqlite3_column_text(stmt, 3));
            const expires_at = c.sqlite3_column_int64(stmt, 4);
            const used = c.sqlite3_column_int(stmt, 5) != 0;
            
            return .{
                .code = try self.allocator.dupe(u8, auth_code),
                .client_id = try self.allocator.dupe(u8, client_id),
                .user_id = user_id,
                .redirect_uri = try self.allocator.dupe(u8, redirect_uri),
                .expires_at = expires_at,
                .used = used,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn markAuthorizationCodeUsed(self: *Database, code: []const u8) !void {
        const sql = "UPDATE authorization_codes SET used = 1 WHERE code = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const code_cstr = try self.allocator.dupeZ(u8, code);
        defer self.allocator.free(code_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, code_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }
    
    // Access Token operations
    pub fn insertAccessToken(self: *Database, token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8) !void {
        const sql = "INSERT INTO access_tokens (token, client_id, user_id, scope, expires_at, refresh_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const token_cstr = try self.allocator.dupeZ(u8, token);
        defer self.allocator.free(token_cstr);
        
        const client_id_cstr = try self.allocator.dupeZ(u8, client_id);
        defer self.allocator.free(client_id_cstr);
        
        const scope_cstr = try self.allocator.dupeZ(u8, scope);
        defer self.allocator.free(scope_cstr);
        
        const now = std.time.timestamp();
        
        _ = c.sqlite3_bind_text(stmt, 1, token_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, client_id_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 3, @intCast(user_id));
        _ = c.sqlite3_bind_text(stmt, 4, scope_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 5, expires_at);
        
        if (refresh_token) |rt| {
            const refresh_token_cstr = try self.allocator.dupeZ(u8, rt);
            defer self.allocator.free(refresh_token_cstr);
            _ = c.sqlite3_bind_text(stmt, 6, refresh_token_cstr, -1, null);
        } else {
            _ = c.sqlite3_bind_null(stmt, 6);
        }
        
        _ = c.sqlite3_bind_int64(stmt, 7, now);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn getAccessToken(self: *Database, token: []const u8) !?struct { token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8 } {
        const sql = "SELECT token, client_id, user_id, scope, expires_at, refresh_token FROM access_tokens WHERE token = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const token_cstr = try self.allocator.dupeZ(u8, token);
        defer self.allocator.free(token_cstr);
        
        _ = c.sqlite3_bind_text(stmt, 1, token_cstr, -1, null);
        
        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            const access_token = std.mem.span(c.sqlite3_column_text(stmt, 0));
            const client_id = std.mem.span(c.sqlite3_column_text(stmt, 1));
            const user_id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 2)));
            const scope = std.mem.span(c.sqlite3_column_text(stmt, 3));
            const expires_at = c.sqlite3_column_int64(stmt, 4);
            
            const refresh_token: ?[]const u8 = if (c.sqlite3_column_type(stmt, 5) == c.SQLITE_NULL) 
                null 
            else 
                try self.allocator.dupe(u8, std.mem.span(c.sqlite3_column_text(stmt, 5)));
            
            return .{
                .token = try self.allocator.dupe(u8, access_token),
                .client_id = try self.allocator.dupe(u8, client_id),
                .user_id = user_id,
                .scope = try self.allocator.dupe(u8, scope),
                .expires_at = expires_at,
                .refresh_token = refresh_token,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }
    
    pub fn insertUser(self: *Database, username: []const u8, email: []const u8) !u64 {
        const sql = "INSERT INTO users (username, email, created_at) VALUES (?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);
        
        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        
        const username_cstr = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_cstr);
        
        const email_cstr = try self.allocator.dupeZ(u8, email);
        defer self.allocator.free(email_cstr);
        
        const now = std.time.timestamp();
        
        _ = c.sqlite3_bind_text(stmt, 1, username_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, email_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 3, now);
        
        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
        
        return @intCast(c.sqlite3_last_insert_rowid(self.db));
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