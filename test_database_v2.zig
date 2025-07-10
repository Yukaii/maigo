const std = @import("std");
const database = @import("src/database_v2.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== TESTING NEW MODULAR DATABASE ===\n", .{});

    // Test database initialization
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    std.debug.print("✅ Database initialized\n", .{});

    // Test user creation
    const user_id = try db.insertUser("testuser", "test@example.com", "password123");
    std.debug.print("✅ User created with ID: {d}\n", .{user_id});

    // Test user retrieval
    const user = try db.getUserByUsername("testuser");
    if (user) |u| {
        defer {
            var mutable_user = u;
            mutable_user.deinit(allocator);
        }
        std.debug.print("✅ User retrieved: {s}\n", .{u.username});
    }

    // Test OAuth client creation
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost");
    std.debug.print("✅ OAuth client created\n", .{});

    // Test OAuth client retrieval
    const client = try db.getOAuthClient("test-client");
    if (client) |c| {
        defer {
            var mutable_client = c;
            mutable_client.deinit(allocator);
        }
        std.debug.print("✅ OAuth client retrieved: {s}\n", .{c.name});
    }

    // Test CLI client fixture
    const cli_client = try db.getOAuthClient("maigo-cli");
    if (cli_client) |c| {
        defer {
            var mutable_client = c;
            mutable_client.deinit(allocator);
        }
        std.debug.print("✅ CLI client fixture exists: {s}\n", .{c.name});
    }

    // THE CRITICAL TEST: Access token with refresh token
    std.debug.print("\n=== TESTING ACCESS TOKEN OPERATIONS ===\n", .{});
    
    const now = std.time.timestamp();
    const expires_at = now + 3600;
    
    std.debug.print("Inserting access token with refresh token...\n", .{});
    try db.insertAccessToken("access-123", "test-client", user_id, "read write", expires_at, "refresh-123");
    
    std.debug.print("Retrieving access token...\n", .{});
    const token = try db.getAccessToken("access-123");
    
    if (token) |t| {
        defer {
            var mutable_token = t;
            mutable_token.deinit(allocator);
        }
        
        std.debug.print("✅ Token retrieved: {s}\n", .{t.token});
        std.debug.print("✅ Client ID: {s}\n", .{t.client_id});
        std.debug.print("✅ Scope: {s}\n", .{t.scope});
        
        if (t.refresh_token) |rt| {
            std.debug.print("✅ Refresh Token: {s}\n", .{rt});
            
            // Character analysis to detect corruption
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
                std.debug.print("🎉 SUCCESS: Refresh token correctly retrieved!\n", .{});
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
            var mutable_token = t;
            mutable_token.deinit(allocator);
        }
        
        std.debug.print("🎉 SUCCESS: Retrieved token by refresh: {s}\n", .{t.token});
    } else {
        std.debug.print("❌ ERROR: Could not retrieve token by refresh\n", .{});
    }

    std.debug.print("\n=== ALL TESTS COMPLETED ===\n", .{});
}