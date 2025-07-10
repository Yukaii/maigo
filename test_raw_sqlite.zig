const std = @import("std");
const c = @cImport({
    @cInclude("sqlite3.h");
});

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== TESTING RAW SQLITE ===\n", .{});

    // Open database
    var db: ?*c.sqlite3 = null;
    var result = c.sqlite3_open(":memory:", &db);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to open database\n", .{});
        return;
    }
    defer _ = c.sqlite3_close(db);
    std.debug.print("✅ Database opened\n", .{});

    // Create table
    result = c.sqlite3_exec(db, "CREATE TABLE test (id INTEGER, name TEXT)", null, null, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to create table: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    std.debug.print("✅ Table created\n", .{});

    // Prepare statement
    const sql = "INSERT INTO test (id, name) VALUES (?, ?)";
    var stmt: ?*c.sqlite3_stmt = null;
    result = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (result != c.SQLITE_OK) {
        std.debug.print("Failed to prepare statement: {s}\n", .{c.sqlite3_errmsg(db)});
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    std.debug.print("✅ Statement prepared\n", .{});

    // Bind parameters
    _ = c.sqlite3_bind_int64(stmt, 1, 123);
    std.debug.print("✅ Int64 bound\n", .{});
    
    const name_cstr = try allocator.dupeZ(u8, "test");
    defer allocator.free(name_cstr);
    _ = c.sqlite3_bind_text(stmt, 2, name_cstr, -1, null);
    std.debug.print("✅ Text bound\n", .{});

    // Execute
    std.debug.print("About to call sqlite3_step...\n", .{});
    result = c.sqlite3_step(stmt);
    std.debug.print("sqlite3_step result: {d}\n", .{result});
    
    if (result == c.SQLITE_DONE) {
        std.debug.print("✅ Insert completed\n", .{});
    } else {
        std.debug.print("❌ Insert failed: {s}\n", .{c.sqlite3_errmsg(db)});
    }

    std.debug.print("=== RAW SQLITE TEST COMPLETED ===\n", .{});
}