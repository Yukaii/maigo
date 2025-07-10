const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== DEEP DEBUG: CHECKING COLUMN-BY-COLUMN ===\n", .{});

    // Open database
    var db: ?*c.sqlite3 = null;
    var result = c.sqlite3_open(":memory:", &db);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to open database\n", .{});
        return;
    }
    defer _ = c.sqlite3_close(db);

    // Create table
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

    // Insert data
    const insert_sql = "INSERT INTO access_tokens (token, refresh_token, client_id, user_id, scope, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)";
    
    var insert_stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, insert_sql, -1, &insert_stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare insert: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(insert_stmt);

    _ = c.sqlite3_bind_text(insert_stmt, 1, "test-token", -1, null);
    _ = c.sqlite3_bind_text(insert_stmt, 2, "test-refresh", -1, null);
    _ = c.sqlite3_bind_text(insert_stmt, 3, "test-client", -1, null);
    _ = c.sqlite3_bind_int64(insert_stmt, 4, 1);
    _ = c.sqlite3_bind_text(insert_stmt, 5, "test-scope", -1, null);
    _ = c.sqlite3_bind_int64(insert_stmt, 6, 1234567890);
    _ = c.sqlite3_bind_int64(insert_stmt, 7, 1234567890);

    result = c.sqlite3_step(insert_stmt);
    if (result != c.SQLITE_DONE) {
        std.debug.print("Failed to insert: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }

    // Now debug retrieval step by step
    const select_sql = "SELECT token, refresh_token, client_id, user_id, scope, expires_at FROM access_tokens WHERE token = ?";
    
    var select_stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, select_sql, -1, &select_stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare select: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(select_stmt);

    _ = c.sqlite3_bind_text(select_stmt, 1, "test-token", -1, null);

    result = c.sqlite3_step(select_stmt);
    if (result == c.SQLITE_ROW) {
        std.debug.print("SUCCESS: Retrieved row\n", .{});
        
        // Check each column individually with extreme care
        std.debug.print("\n=== COLUMN 0 (token) ===\n", .{});
        const col0_type = c.sqlite3_column_type(select_stmt, 0);
        std.debug.print("Type: {d}\n", .{col0_type});
        if (col0_type == c.SQLITE_TEXT) {
            const col0_ptr = c.sqlite3_column_text(select_stmt, 0);
            const col0_span = std.mem.span(col0_ptr);
            std.debug.print("Value: '{s}'\n", .{col0_span});
            const col0_copy = try allocator.dupe(u8, col0_span);
            defer allocator.free(col0_copy);
            std.debug.print("Copy: '{s}'\n", .{col0_copy});
        }
        
        std.debug.print("\n=== COLUMN 1 (refresh_token) ===\n", .{});
        const col1_type = c.sqlite3_column_type(select_stmt, 1);
        std.debug.print("Type: {d} (TEXT={d}, NULL={d})\n", .{col1_type, c.SQLITE_TEXT, c.SQLITE_NULL});
        if (col1_type == c.SQLITE_TEXT) {
            const col1_ptr = c.sqlite3_column_text(select_stmt, 1);
            std.debug.print("Pointer: {*}\n", .{col1_ptr});
            const col1_bytes = c.sqlite3_column_bytes(select_stmt, 1);
            std.debug.print("Bytes: {d}\n", .{col1_bytes});
            
            // Try different ways to read the data
            std.debug.print("Method 1 - std.mem.span:\n", .{});
            const col1_span = std.mem.span(col1_ptr);
            std.debug.print("  Span length: {d}\n", .{col1_span.len});
            std.debug.print("  Raw bytes: ", .{});
            for (col1_span, 0..) |byte, i| {
                std.debug.print("{d} ", .{byte});
                if (i >= 15) break;
            }
            std.debug.print("\n  String: '{s}'\n", .{col1_span});
            
            std.debug.print("Method 2 - manual slice:\n", .{});
            const col1_manual = col1_ptr[0..@intCast(col1_bytes)];
            std.debug.print("  Manual length: {d}\n", .{col1_manual.len});
            std.debug.print("  Raw bytes: ", .{});
            for (col1_manual, 0..) |byte, i| {
                std.debug.print("{d} ", .{byte});
                if (i >= 15) break;
            }
            std.debug.print("\n  String: '{s}'\n", .{col1_manual});
            
            // Try to copy immediately
            const col1_copy = try allocator.dupe(u8, col1_span);
            defer allocator.free(col1_copy);
            std.debug.print("  Copy: '{s}'\n", .{col1_copy});
        }
        
        std.debug.print("\n=== COLUMN 2 (client_id) ===\n", .{});
        const col2_type = c.sqlite3_column_type(select_stmt, 2);
        std.debug.print("Type: {d}\n", .{col2_type});
        if (col2_type == c.SQLITE_TEXT) {
            const col2_ptr = c.sqlite3_column_text(select_stmt, 2);
            const col2_span = std.mem.span(col2_ptr);
            std.debug.print("Value: '{s}'\n", .{col2_span});
        }
        
    } else {
        std.debug.print("Failed to retrieve row: {d}\n", .{result});
    }
}