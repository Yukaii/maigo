const std = @import("std");
const database = @import("src/database_v2.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== SIMPLE DATABASE TEST ===\n", .{});

    // Test database initialization
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    std.debug.print("✅ Database initialized\n", .{});

    // Test user creation
    const user_id = try db.insertUser("testuser", "test@example.com", "password123");
    std.debug.print("✅ User created with ID: {d}\n", .{user_id});

    // Test OAuth client creation
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost");
    std.debug.print("✅ OAuth client created\n", .{});

    // THE CRITICAL TEST: Access token with refresh token
    std.debug.print("\n=== TESTING ACCESS TOKEN ===\n", .{});
    
    const now = std.time.timestamp();
    const expires_at = now + 3600;
    
    try db.insertAccessToken("access-123", "test-client", user_id, "read write", expires_at, "refresh-123");
    std.debug.print("✅ Access token inserted\n", .{});
    
    const token = try db.getAccessToken("access-123");
    
    if (token) |t| {
        defer {
            var mutable_token = t;
            mutable_token.deinit(allocator);
        }
        
        std.debug.print("✅ Token: {s}\n", .{t.token});
        
        if (t.refresh_token) |rt| {
            if (std.mem.eql(u8, rt, "refresh-123")) {
                std.debug.print("🎉 SUCCESS: Refresh token correct!\n", .{});
            } else {
                std.debug.print("❌ FAIL: Expected 'refresh-123', got '{s}'\n", .{rt});
            }
        } else {
            std.debug.print("❌ FAIL: Refresh token is null\n", .{});
        }
    } else {
        std.debug.print("❌ FAIL: Could not retrieve token\n", .{});
    }

    std.debug.print("=== TEST COMPLETED ===\n", .{});
}