const std = @import("std");
const core = @import("src/db/core.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== TESTING CORE DATABASE ===\n", .{});

    // Test core database initialization
    var db = try core.Database.init(allocator, ":memory:");
    defer db.deinit();

    std.debug.print("✅ Core database initialized\n", .{});

    // Test basic SQL execution
    try db.exec("CREATE TABLE test (id INTEGER, name TEXT)");
    std.debug.print("✅ Table created\n", .{});

    // Test statement preparation
    var stmt = try core.Statement.prepare(&db, "INSERT INTO test (id, name) VALUES (?, ?)");
    defer stmt.deinit();

    stmt.bindInt64(1, 123);
    try stmt.bindText(2, "test");
    _ = try stmt.step();

    std.debug.print("✅ Data inserted\n", .{});

    // Test retrieval
    var select_stmt = try core.Statement.prepare(&db, "SELECT id, name FROM test WHERE id = ?");
    defer select_stmt.deinit();

    select_stmt.bindInt64(1, 123);
    const result = try select_stmt.step();

    if (result == core.c.SQLITE_ROW) {
        const id = select_stmt.getInt64(0);
        const name = select_stmt.getText(1);
        
        std.debug.print("✅ Retrieved: id={d}, name={s}\n", .{id, name orelse "NULL"});
    }

    std.debug.print("=== CORE TEST COMPLETED ===\n", .{});
}