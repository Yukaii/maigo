const std = @import("std");
const lib = @import("src/root.zig");
const postgres = @import("src/postgres.zig");
const postgres_schema = @import("src/postgres_schema.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("PostgreSQL Debug Test\n", .{});
    std.debug.print("===================\n\n", .{});

    const config = postgres.DatabaseConfig{
        .host = "localhost",
        .database = "maigo_test",
        .username = std.posix.getenv("USER") orelse "postgres",
        .password = "",
    };

    std.debug.print("Connecting to PostgreSQL...\n", .{});
    var db = postgres.Database.init(allocator, config) catch |err| {
        std.debug.print("Connection failed: {}\n", .{err});
        return;
    };
    defer db.deinit();
    
    std.debug.print("✓ Connected successfully\n", .{});

    std.debug.print("Creating schema...\n", .{});
    postgres_schema.createTables(&db) catch |err| {
        std.debug.print("Schema creation failed: {}\n", .{err});
        return;
    };
    
    std.debug.print("✓ Schema created\n", .{});

    std.debug.print("Testing basic query...\n", .{});
    const conn = db.pool.acquire() catch |err| {
        std.debug.print("Failed to acquire connection: {}\n", .{err});
        return;
    };
    defer db.pool.release(conn);

    const result = conn.query("SELECT 1 as test_value", .{}) catch |err| {
        std.debug.print("Query failed: {}\n", .{err});
        return;
    };

    if (try result.next()) |row| {
        const test_value = row.get(i32, 0);
        std.debug.print("✓ Basic query result: {}\n", .{test_value});
    }

    std.debug.print("\nAll basic operations successful!\n", .{});
}