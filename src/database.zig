const std = @import("std");
const testing = std.testing;
const c = @cImport({
    @cInclude("sqlite3.h");
});

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
    password_hash: []const u8,
    created_at: i64,

    pub fn deinit(self: *User, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.email);
        allocator.free(self.password_hash);
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
            \\    password_hash TEXT NOT NULL,
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
            \\    refresh_token TEXT,
            \\    client_id TEXT NOT NULL,
            \\    user_id INTEGER NOT NULL,
            \\    scope TEXT NOT NULL,
            \\    expires_at INTEGER NOT NULL,
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

        // Insert CLI client fixture
        try self.insertCliClientFixture();
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

    fn insertCliClientFixture(self: *Database) !void {
        // Check if CLI client already exists
        const existing_client = try self.getOAuthClient(CLI_CLIENT_ID);
        if (existing_client) |client_data| {
            // Client already exists, clean up and return
            self.allocator.free(client_data.id);
            self.allocator.free(client_data.secret);
            self.allocator.free(client_data.name);
            self.allocator.free(client_data.redirect_uri);
            return;
        }

        // Insert CLI client fixture
        const sql = "INSERT OR IGNORE INTO oauth_clients (id, secret, name, redirect_uri, created_at) VALUES (?, ?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);

        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        const client_id_cstr = try self.allocator.dupeZ(u8, CLI_CLIENT_ID);
        defer self.allocator.free(client_id_cstr);

        const client_secret_cstr = try self.allocator.dupeZ(u8, CLI_CLIENT_SECRET);
        defer self.allocator.free(client_secret_cstr);

        const client_name_cstr = try self.allocator.dupeZ(u8, CLI_CLIENT_NAME);
        defer self.allocator.free(client_name_cstr);

        const redirect_uri_cstr = try self.allocator.dupeZ(u8, CLI_CLIENT_REDIRECT_URI);
        defer self.allocator.free(redirect_uri_cstr);

        const now = std.time.timestamp();

        _ = c.sqlite3_bind_text(stmt, 1, client_id_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, client_secret_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 3, client_name_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 4, redirect_uri_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 5, now);

        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        std.debug.print("CLI OAuth client fixture inserted: {s}\n", .{CLI_CLIENT_ID});
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
        const sql = "INSERT INTO access_tokens (token, refresh_token, client_id, user_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
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
        
        if (refresh_token) |rt| {
            const refresh_token_cstr = try self.allocator.dupeZ(u8, rt);
            defer self.allocator.free(refresh_token_cstr);
            _ = c.sqlite3_bind_text(stmt, 2, refresh_token_cstr, -1, null);
        } else {
            _ = c.sqlite3_bind_null(stmt, 2);
        }
        
        _ = c.sqlite3_bind_text(stmt, 3, client_id_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 4, @intCast(user_id));
        _ = c.sqlite3_bind_text(stmt, 5, scope_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 6, expires_at);
        _ = c.sqlite3_bind_int64(stmt, 7, now);

        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    pub fn getAccessToken(self: *Database, token: []const u8) !?struct { token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8 } {
        const sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at FROM access_tokens WHERE token = ?";
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
            // Extract data column by column, copying immediately to avoid invalidation
            const access_token = try self.allocator.dupe(u8, std.mem.span(c.sqlite3_column_text(stmt, 0)));
            
            const refresh_token: ?[]u8 = blk: {
                const col_type = c.sqlite3_column_type(stmt, 1);
                if (col_type == c.SQLITE_NULL) {
                    break :blk null;
                } else {
                    const refresh_token_ptr = c.sqlite3_column_text(stmt, 1);
                    const refresh_token_span = std.mem.span(refresh_token_ptr);
                    break :blk try self.allocator.dupe(u8, refresh_token_span);
                }
            };
            
            const client_id = try self.allocator.dupe(u8, std.mem.span(c.sqlite3_column_text(stmt, 2)));
            
            // Get integer value before next text column
            const user_id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 3)));
            
            const scope = try self.allocator.dupe(u8, std.mem.span(c.sqlite3_column_text(stmt, 4)));
            
            const expires_at = c.sqlite3_column_int64(stmt, 5);

            return .{
                .token = access_token,
                .client_id = client_id,
                .user_id = user_id,
                .scope = scope,
                .expires_at = expires_at,
                .refresh_token = refresh_token,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }

    pub fn getAccessTokenByRefresh(self: *Database, refresh_token: []const u8) !?struct { token: []const u8, client_id: []const u8, user_id: u64, scope: []const u8, expires_at: i64, refresh_token: ?[]const u8 } {
        const sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at FROM access_tokens WHERE refresh_token = ?";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);

        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        const refresh_token_cstr = try self.allocator.dupeZ(u8, refresh_token);
        defer self.allocator.free(refresh_token_cstr);

        _ = c.sqlite3_bind_text(stmt, 1, refresh_token_cstr, -1, null);

        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            // Extract ALL text columns FIRST to avoid pointer invalidation
            const access_token_span = std.mem.span(c.sqlite3_column_text(stmt, 0));
            const access_token = try self.allocator.dupe(u8, access_token_span);
            
            const stored_refresh_token: ?[]u8 = if (c.sqlite3_column_type(stmt, 1) == c.SQLITE_NULL)
                null
            else blk: {
                const refresh_token_span = std.mem.span(c.sqlite3_column_text(stmt, 1));
                break :blk try self.allocator.dupe(u8, refresh_token_span);
            };
            
            const client_id_span = std.mem.span(c.sqlite3_column_text(stmt, 2));
            const client_id = try self.allocator.dupe(u8, client_id_span);
            
            const scope_span = std.mem.span(c.sqlite3_column_text(stmt, 4));
            const scope = try self.allocator.dupe(u8, scope_span);
            
            // Now safe to call integer functions
            const user_id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 3)));
            const expires_at = c.sqlite3_column_int64(stmt, 5);

            return .{
                .token = access_token,
                .client_id = client_id,
                .user_id = user_id,
                .scope = scope,
                .expires_at = expires_at,
                .refresh_token = stored_refresh_token,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
    }

    pub fn revokeAccessToken(self: *Database, token: []const u8) !void {
        const sql = "DELETE FROM access_tokens WHERE token = ?";
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
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
    }

    pub fn insertUser(self: *Database, username: []const u8, email: []const u8, password_hash: []const u8) !u64 {
        const sql = "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)";
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);

        var stmt: ?*c.sqlite3_stmt = null;
        var result = c.sqlite3_prepare_v2(self.db, sql_cstr, -1, &stmt, null);
        if (result != c.SQLITE_OK) {
            std.debug.print("SQLite prepare failed in insertUser: {s}\n", .{c.sqlite3_errmsg(self.db)});
            std.debug.print("SQL: {s}\n", .{sql_cstr});
            std.debug.print("Database pointer: {*}\n", .{self.db});
            return DatabaseError.PrepareFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        const username_cstr = try self.allocator.dupeZ(u8, username);
        defer self.allocator.free(username_cstr);

        const email_cstr = try self.allocator.dupeZ(u8, email);
        defer self.allocator.free(email_cstr);

        const password_hash_cstr = try self.allocator.dupeZ(u8, password_hash);
        defer self.allocator.free(password_hash_cstr);

        const now = std.time.timestamp();

        _ = c.sqlite3_bind_text(stmt, 1, username_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 2, email_cstr, -1, null);
        _ = c.sqlite3_bind_text(stmt, 3, password_hash_cstr, -1, null);
        _ = c.sqlite3_bind_int64(stmt, 4, now);

        result = c.sqlite3_step(stmt);
        if (result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }

        return @intCast(c.sqlite3_last_insert_rowid(self.db));
    }

    pub fn getUserByUsername(self: *Database, username: []const u8) !?User {
        const sql = "SELECT id, username, email, password_hash, created_at FROM users WHERE username = ?";
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

        _ = c.sqlite3_bind_text(stmt, 1, username_cstr, -1, null);

        result = c.sqlite3_step(stmt);
        if (result == c.SQLITE_ROW) {
            const id = @as(u64, @intCast(c.sqlite3_column_int64(stmt, 0)));
            const user_username = std.mem.span(c.sqlite3_column_text(stmt, 1));
            const email = std.mem.span(c.sqlite3_column_text(stmt, 2));
            const password_hash = std.mem.span(c.sqlite3_column_text(stmt, 3));
            const created_at = c.sqlite3_column_int64(stmt, 4);

            return User{
                .id = id,
                .username = try self.allocator.dupe(u8, user_username),
                .email = try self.allocator.dupe(u8, email),
                .password_hash = try self.allocator.dupe(u8, password_hash),
                .created_at = created_at,
            };
        } else if (result == c.SQLITE_DONE) {
            return null;
        } else {
            return DatabaseError.StepFailed;
        }
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

test "database user operations" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Test inserting a user
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword123");
    try testing.expect(user_id > 0);

    // Test retrieving the user
    var user = try db.getUserByUsername("testuser");
    try testing.expect(user != null);

    if (user) |*u| {
        defer u.deinit(allocator);
        try testing.expectEqualStrings("testuser", u.username);
        try testing.expectEqualStrings("test@example.com", u.email);
        try testing.expectEqualStrings("hashedpassword123", u.password_hash);
        try testing.expect(u.id == user_id);
        try testing.expect(u.created_at > 0);
    }

    // Test retrieving non-existent user
    const nonexistent_user = try db.getUserByUsername("nonexistent");
    try testing.expect(nonexistent_user == null);

    // Test duplicate username should fail
    const duplicate_result = db.insertUser("testuser", "other@example.com", "otherpassword");
    try testing.expectError(DatabaseError.StepFailed, duplicate_result);

    // Test duplicate email should fail
    const duplicate_email_result = db.insertUser("otheruser", "test@example.com", "otherpassword");
    try testing.expectError(DatabaseError.StepFailed, duplicate_email_result);
}

test "database oauth client operations" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Test CLI client fixture is automatically inserted
    const cli_client = try db.getOAuthClient("maigo-cli");
    try testing.expect(cli_client != null);

    if (cli_client) |client| {
        try testing.expectEqualStrings("maigo-cli", client.id);
        try testing.expectEqualStrings("cli-secret-fixed-deterministic-value-for-embedded-client", client.secret);
        try testing.expectEqualStrings("Maigo CLI", client.name);
        try testing.expectEqualStrings("urn:ietf:wg:oauth:2.0:oob", client.redirect_uri);
        
        allocator.free(client.id);
        allocator.free(client.secret);
        allocator.free(client.name);
        allocator.free(client.redirect_uri);
    }

    // Test inserting a custom OAuth client
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    const custom_client = try db.getOAuthClient("test-client");
    try testing.expect(custom_client != null);

    if (custom_client) |client| {
        try testing.expectEqualStrings("test-client", client.id);
        try testing.expectEqualStrings("test-secret", client.secret);
        try testing.expectEqualStrings("Test Client", client.name);
        try testing.expectEqualStrings("http://localhost:3000/callback", client.redirect_uri);
        
        allocator.free(client.id);
        allocator.free(client.secret);
        allocator.free(client.name);
        allocator.free(client.redirect_uri);
    }

    // Test retrieving non-existent client
    const nonexistent_client = try db.getOAuthClient("nonexistent");
    try testing.expect(nonexistent_client == null);
}

test "database authorization code operations" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test user and client first
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword");
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    // Test inserting authorization code
    const now = std.time.timestamp();
    const expires_at = now + 600; // 10 minutes
    try db.insertAuthorizationCode("auth-code-123", "test-client", user_id, "http://localhost:3000/callback", expires_at);

    // Test retrieving authorization code
    const auth_code = try db.getAuthorizationCode("auth-code-123");
    try testing.expect(auth_code != null);

    if (auth_code) |code| {
        try testing.expectEqualStrings("auth-code-123", code.code);
        try testing.expectEqualStrings("test-client", code.client_id);
        try testing.expect(code.user_id == user_id);
        try testing.expectEqualStrings("http://localhost:3000/callback", code.redirect_uri);
        try testing.expect(code.expires_at == expires_at);
        try testing.expect(!code.used);

        allocator.free(code.code);
        allocator.free(code.client_id);
        allocator.free(code.redirect_uri);
    }

    // Test marking authorization code as used
    try db.markAuthorizationCodeUsed("auth-code-123");

    const used_code = try db.getAuthorizationCode("auth-code-123");
    try testing.expect(used_code != null);

    if (used_code) |code| {
        try testing.expect(code.used);
        
        allocator.free(code.code);
        allocator.free(code.client_id);
        allocator.free(code.redirect_uri);
    }

    // Test retrieving non-existent authorization code
    const nonexistent_code = try db.getAuthorizationCode("nonexistent");
    try testing.expect(nonexistent_code == null);
}

test "database access token operations" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test user and client first
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword");
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    // Test inserting access token with refresh token
    const now = std.time.timestamp();
    const expires_at = now + 3600; // 1 hour
    try db.insertAccessToken("access-token-123", "test-client", user_id, "url:read url:write", expires_at, "refresh-token-123");

    // Test retrieving access token
    const access_token = try db.getAccessToken("access-token-123");
    try testing.expect(access_token != null);

    if (access_token) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        try testing.expectEqualStrings("access-token-123", token.token);
        try testing.expectEqualStrings("test-client", token.client_id);
        try testing.expect(token.user_id == user_id);
        try testing.expectEqualStrings("url:read url:write", token.scope);
        try testing.expect(token.expires_at == expires_at);
        try testing.expect(token.refresh_token != null);
        if (token.refresh_token) |rt| {
            try testing.expectEqualStrings("refresh-token-123", rt);
        }
    }

    // Test retrieving access token by refresh token
    const token_by_refresh = try db.getAccessTokenByRefresh("refresh-token-123");
    try testing.expect(token_by_refresh != null);

    if (token_by_refresh) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        try testing.expectEqualStrings("access-token-123", token.token);
    }

    // Test inserting access token without refresh token
    try db.insertAccessToken("access-token-456", "test-client", user_id, "url:read", expires_at, null);

    const no_refresh_token = try db.getAccessToken("access-token-456");
    try testing.expect(no_refresh_token != null);

    if (no_refresh_token) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
        }
        
        try testing.expect(token.refresh_token == null);
    }

    // Test revoking access token
    try db.revokeAccessToken("access-token-123");

    const revoked_token = try db.getAccessToken("access-token-123");
    try testing.expect(revoked_token == null);

    // Test retrieving non-existent tokens
    const nonexistent_token = try db.getAccessToken("nonexistent");
    try testing.expect(nonexistent_token == null);

    const nonexistent_refresh = try db.getAccessTokenByRefresh("nonexistent");
    try testing.expect(nonexistent_refresh == null);
}

test "database url operations with user association" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test user
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword");

    // Test inserting URL with user association
    const url_id = try db.insertUrl("user123", "https://example.com/user", user_id);
    try testing.expect(url_id > 0);

    // Test retrieving the URL
    var url = try db.getUrlByShortCode("user123");
    try testing.expect(url != null);

    if (url) |*u| {
        defer u.deinit(allocator);
        try testing.expectEqualStrings("user123", u.short_code);
        try testing.expectEqualStrings("https://example.com/user", u.target_url);
        try testing.expect(u.user_id == user_id);
        try testing.expect(u.hits == 0);
    }

    // Test multiple hit increments
    try db.incrementHits("user123");
    try db.incrementHits("user123");
    try db.incrementHits("user123");

    var updated_url = try db.getUrlByShortCode("user123");
    try testing.expect(updated_url != null);

    if (updated_url) |*u| {
        defer u.deinit(allocator);
        try testing.expect(u.hits == 3);
    }
}

test "database edge cases and error conditions" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Test inserting URL with duplicate short code
    _ = try db.insertUrl("duplicate", "https://first.com", null);
    const duplicate_result = db.insertUrl("duplicate", "https://second.com", null);
    try testing.expectError(DatabaseError.StepFailed, duplicate_result);

    // Test incrementing hits for non-existent URL (should not error)
    try db.incrementHits("nonexistent");

    // Test empty strings (should work as valid data)
    const empty_user_id = try db.insertUser("emptyuser", "", "");
    try testing.expect(empty_user_id > 0);

    var empty_user = try db.getUserByUsername("emptyuser");
    try testing.expect(empty_user != null);
    if (empty_user) |*u| {
        defer u.deinit(allocator);
        try testing.expectEqualStrings("", u.email);
        try testing.expectEqualStrings("", u.password_hash);
    }
}

test "database simple refresh token test" {
    const allocator = testing.allocator;

    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test user and client first
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword");
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    // Test simple refresh token insertion and retrieval
    const now = std.time.timestamp();
    const expires_at = now + 3600;
    
    // Insert WITHOUT refresh token first to see if that works
    try db.insertAccessToken("token-no-refresh", "test-client", user_id, "scope", expires_at, null);
    
    const token_no_refresh = try db.getAccessToken("token-no-refresh");
    try testing.expect(token_no_refresh != null);
    if (token_no_refresh) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
        }
        
        try testing.expect(token.refresh_token == null);
    }

    // Now test WITH a simple refresh token
    try db.insertAccessToken("token-with-refresh", "test-client", user_id, "scope", expires_at, "simple");
    
    const token_with_refresh = try db.getAccessToken("token-with-refresh");
    try testing.expect(token_with_refresh != null);
    if (token_with_refresh) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        try testing.expect(token.refresh_token != null);
        if (token.refresh_token) |rt| {
            try testing.expectEqualStrings("simple", rt);
        }
    }
}

test "database cli client credentials" {
    const allocator = testing.allocator;

    // Test CLI client credentials fixture
    const cli_creds = getCliClientCredentials();
    try testing.expectEqualStrings("maigo-cli", cli_creds.client_id);
    try testing.expectEqualStrings("cli-secret-fixed-deterministic-value-for-embedded-client", cli_creds.client_secret);
    try testing.expectEqualStrings("Maigo CLI", cli_creds.name);
    try testing.expectEqualStrings("urn:ietf:wg:oauth:2.0:oob", cli_creds.redirect_uri);

    // Test that CLI client is automatically inserted during database initialization
    var db = try Database.init(allocator, ":memory:");
    defer db.deinit();

    const inserted_cli_client = try db.getOAuthClient("maigo-cli");
    try testing.expect(inserted_cli_client != null);

    if (inserted_cli_client) |client| {
        try testing.expectEqualStrings(cli_creds.client_id, client.id);
        try testing.expectEqualStrings(cli_creds.client_secret, client.secret);
        try testing.expectEqualStrings(cli_creds.name, client.name);
        try testing.expectEqualStrings(cli_creds.redirect_uri, client.redirect_uri);

        allocator.free(client.id);
        allocator.free(client.secret);
        allocator.free(client.name);
        allocator.free(client.redirect_uri);
    }
}
