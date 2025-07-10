const std = @import("std");
pub const c = @cImport({
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

/// Core database connection wrapper
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

        return Database{
            .db = db,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Database) void {
        if (self.db) |db| {
            _ = c.sqlite3_close(db);
        }
    }

    pub fn exec(self: *Database, sql: []const u8) !void {
        const sql_cstr = try self.allocator.dupeZ(u8, sql);
        defer self.allocator.free(sql_cstr);

        const result = c.sqlite3_exec(self.db, sql_cstr, null, null, null);
        if (result != c.SQLITE_OK) {
            std.debug.print("SQL execution failed: {s}\n", .{c.sqlite3_errmsg(self.db)});
            std.debug.print("SQL: {s}\n", .{sql_cstr});
            return DatabaseError.ExecFailed;
        }
    }
};

/// Safe statement wrapper that ensures proper cleanup
pub const Statement = struct {
    stmt: ?*c.sqlite3_stmt,
    allocator: std.mem.Allocator,

    pub fn prepare(db: *Database, sql: []const u8) !Statement {
        std.debug.print("Preparing SQL: {s}\n", .{sql});
        
        const sql_cstr = try db.allocator.dupeZ(u8, sql);
        defer db.allocator.free(sql_cstr);
        
        std.debug.print("SQL as C string: {s}\n", .{sql_cstr});

        var stmt: ?*c.sqlite3_stmt = null;
        std.debug.print("Calling sqlite3_prepare_v2...\n", .{});
        const result = c.sqlite3_prepare_v2(db.db, sql_cstr, -1, &stmt, null);
        std.debug.print("sqlite3_prepare_v2 result: {d}\n", .{result});
        
        if (result != c.SQLITE_OK) {
            std.debug.print("Statement preparation failed: {s}\n", .{c.sqlite3_errmsg(db.db)});
            std.debug.print("SQL: {s}\n", .{sql_cstr});
            return DatabaseError.PrepareFailed;
        }

        std.debug.print("Statement prepared successfully\n", .{});
        return Statement{
            .stmt = stmt,
            .allocator = db.allocator,
        };
    }

    pub fn deinit(self: *Statement) void {
        if (self.stmt) |stmt| {
            _ = c.sqlite3_finalize(stmt);
        }
    }

    pub fn bindText(self: *Statement, index: i32, value: []const u8) !void {
        std.debug.print("Binding text at index {d}: {s}\n", .{index, value});
        const value_cstr = try self.allocator.dupeZ(u8, value);
        defer self.allocator.free(value_cstr);
        std.debug.print("Calling sqlite3_bind_text...\n", .{});
        _ = c.sqlite3_bind_text(self.stmt, index, value_cstr, -1, null);
        std.debug.print("Text bound successfully\n", .{});
    }

    pub fn bindInt64(self: *Statement, index: i32, value: i64) void {
        _ = c.sqlite3_bind_int64(self.stmt, index, value);
    }

    pub fn bindNull(self: *Statement, index: i32) void {
        _ = c.sqlite3_bind_null(self.stmt, index);
    }

    pub fn step(self: *Statement) !c_int {
        std.debug.print("Calling sqlite3_step...\n", .{});
        const result = c.sqlite3_step(self.stmt);
        std.debug.print("sqlite3_step result: {d}\n", .{result});
        if (result != c.SQLITE_ROW and result != c.SQLITE_DONE) {
            return DatabaseError.StepFailed;
        }
        std.debug.print("Step completed successfully\n", .{});
        return result;
    }

    pub fn reset(self: *Statement) void {
        _ = c.sqlite3_reset(self.stmt);
    }

    pub fn getText(self: *Statement, index: i32) ?[]const u8 {
        const ptr = c.sqlite3_column_text(self.stmt, index);
        if (ptr == null) return null;
        return std.mem.span(ptr);
    }

    pub fn getTextAlloc(self: *Statement, index: i32) !?[]u8 {
        const text = self.getText(index) orelse return null;
        return try self.allocator.dupe(u8, text);
    }

    pub fn getInt64(self: *Statement, index: i32) i64 {
        return c.sqlite3_column_int64(self.stmt, index);
    }

    pub fn isNull(self: *Statement, index: i32) bool {
        return c.sqlite3_column_type(self.stmt, index) == c.SQLITE_NULL;
    }

    pub fn getLastInsertId(self: *Statement, db: *Database) u64 {
        _ = self;
        return @intCast(c.sqlite3_last_insert_rowid(db.db));
    }
};