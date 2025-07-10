const std = @import("std");
const database = @import("src/database.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== TESTING FIXED ORIGINAL DATABASE ===\n", .{});

    // Test database initialization (this automatically creates CLI fixture)
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    std.debug.print("✅ Database initialized\n", .{});

    // Create test user and client for the test
    const user_id = try db.insertUser("testuser", "test@example.com", "password123");
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost");
    
    std.debug.print("✅ Prerequisites created\n", .{});

    // THE CRITICAL TEST: Access token with refresh token
    const now = std.time.timestamp();
    const expires_at = now + 3600;
    
    std.debug.print("Inserting access token with refresh token...\n", .{});
    try db.insertAccessToken("access-123", "test-client", user_id, "read write", expires_at, "refresh-123");
    
    std.debug.print("Retrieving access token...\n", .{});
    const token = try db.getAccessToken("access-123");
    
    if (token) |t| {
        defer {
            allocator.free(t.token);
            allocator.free(t.client_id);
            allocator.free(t.scope);
            if (t.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        std.debug.print("✅ Token: {s}\n", .{t.token});
        std.debug.print("✅ Client ID: {s}\n", .{t.client_id});
        std.debug.print("✅ Scope: {s}\n", .{t.scope});
        
        if (t.refresh_token) |rt| {
            // Check for corruption pattern
            var is_corrupted = false;
            for (rt) |char| {
                if (char == 170) { // 0xAA corruption pattern
                    is_corrupted = true;
                    break;
                }
            }
            
            if (is_corrupted) {
                std.debug.print("❌ CORRUPTION DETECTED: Found 0xAA bytes\n", .{});
            } else if (std.mem.eql(u8, rt, "refresh-123")) {
                std.debug.print("🎉 SUCCESS: Refresh token correctly retrieved: '{s}'\n", .{rt});
            } else {
                std.debug.print("❌ MISMATCH: Expected 'refresh-123', got '{s}'\n", .{rt});
            }
        } else {
            std.debug.print("❌ ERROR: Refresh token is null\n", .{});
        }
    } else {
        std.debug.print("❌ ERROR: Could not retrieve access token\n", .{});
    }

    // Test retrieval by refresh token
    std.debug.print("\nTesting retrieval by refresh token...\n", .{});
    const token_by_refresh = try db.getAccessTokenByRefresh("refresh-123");
    
    if (token_by_refresh) |t| {
        defer {
            allocator.free(t.token);
            allocator.free(t.client_id);
            allocator.free(t.scope);
            if (t.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        std.debug.print("🎉 SUCCESS: Retrieved token by refresh: {s}\n", .{t.token});
    } else {
        std.debug.print("❌ ERROR: Could not retrieve token by refresh\n", .{});
    }

    std.debug.print("\n=== ORIGINAL DATABASE TEST COMPLETED ===\n", .{});
}