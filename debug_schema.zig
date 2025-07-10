const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    _ = gpa.allocator();

    // Open database
    var db: ?*c.sqlite3 = null;
    var result = c.sqlite3_open(":memory:", &db);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to open database\n", .{});
        return;
    }
    defer _ = c.sqlite3_close(db);

    // Create table manually to match current schema
    const create_table = 
        \\CREATE TABLE access_tokens (
        \\    token TEXT PRIMARY KEY,
        \\    refresh_token TEXT,
        \\    client_id TEXT NOT NULL,
        \\    user_id INTEGER NOT NULL,
        \\    scope TEXT NOT NULL,
        \\    expires_at INTEGER NOT NULL,
        \\    created_at INTEGER NOT NULL
        \\);
    ;

    result = c.sqlite3_exec(db, create_table, null, null, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to create table: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }

    // Check schema
    const pragma_query = "PRAGMA table_info(access_tokens)";
    var stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, pragma_query, -1, &stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare pragma: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);

    std.debug.print("Table schema for access_tokens:\n", .{});
    while (c.sqlite3_step(stmt) == c.SQLITE_ROW) {
        const cid = c.sqlite3_column_int(stmt, 0);
        const name = std.mem.span(c.sqlite3_column_text(stmt, 1));
        const type_name = std.mem.span(c.sqlite3_column_text(stmt, 2));
        std.debug.print("  Column {d}: {s} ({s})\n", .{cid, name, type_name});
    }

    // Now test insertion
    const insert_sql = "INSERT INTO access_tokens (token, refresh_token, client_id, user_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    var insert_stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare insert: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(insert_stmt);

    _ = c.sqlite3_bind_text(insert_stmt, 1, "access-token-123", -1, null);
    _ = c.sqlite3_bind_text(insert_stmt, 2, "refresh-token-123", -1, null);
    _ = c.sqlite3_bind_text(insert_stmt, 3, "test-client", -1, null);
    _ = c.sqlite3_bind_int64(insert_stmt, 4, 1);
    _ = c.sqlite3_bind_text(insert_stmt, 5, "url:read url:write", -1, null);
    _ = c.sqlite3_bind_int64(insert_stmt, 6, 1234567890);
    _ = c.sqlite3_bind_int64(insert_stmt, 7, 1234567890);

    result = c.sqlite3_step(insert_stmt);
    if (result != c.SQLITE_DONE) {
        std.debug.print("Failed to insert: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }

    std.debug.print("✅ Data inserted successfully\n", .{});

    // Now test retrieval
    const select_sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at FROM access_tokens WHERE token = ?";
    
    var select_stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare select: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(select_stmt);

    _ = c.sqlite3_bind_text(select_stmt, 1, "access-token-123", -1, null);

    result = c.sqlite3_step(select_stmt);
    if (result == c.SQLITE_ROW) {
        std.debug.print("Retrieved data:\n", .{});
        
        for (0..6) |i| {
            const col_type = c.sqlite3_column_type(select_stmt, @intCast(i));
            if (col_type == c.SQLITE_TEXT) {
                const text_span = std.mem.span(c.sqlite3_column_text(select_stmt, @intCast(i)));
                std.debug.print("  Column {d}: '{s}'\n", .{i, text_span});
            } else if (col_type == c.SQLITE_INTEGER) {
                const int_val = c.sqlite3_column_int64(select_stmt, @intCast(i));
                std.debug.print("  Column {d}: {d}\n", .{i, int_val});
            } else {
                std.debug.print("  Column {d}: NULL\n", .{i});
            }
        }
        
        // Focus on refresh token (column 1)
        const refresh_token_span = std.mem.span(c.sqlite3_column_text(select_stmt, 1));
        std.debug.print("\nRefresh token analysis:\n", .{});
        std.debug.print("  Value: '{s}'\n", .{refresh_token_span});
        std.debug.print("  Length: {d}\n", .{refresh_token_span.len});
        std.debug.print("  Expected: 'refresh-token-123'\n", .{});
        std.debug.print("  Match: {}\n", .{std.mem.eql(u8, refresh_token_span, "refresh-token-123")});
    }
}