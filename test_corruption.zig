const std = @import("std");
const database = @import("src/database.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Test database corruption issue
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    // Create test user and client
    const user_id = try db.insertUser("testuser", "test@example.com", "hashedpassword");
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost:3000/callback");

    // Test inserting access token with refresh token
    const now = std.time.timestamp();
    const expires_at = now + 3600; // 1 hour
    
    std.debug.print("Inserting access token with refresh token 'refresh-token-123'...\n", .{});
    try db.insertAccessToken("access-token-123", "test-client", user_id, "url:read url:write", expires_at, "refresh-token-123");

    // Test retrieving access token
    std.debug.print("Retrieving access token...\n", .{});
    const access_token = try db.getAccessToken("access-token-123");
    
    if (access_token) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        std.debug.print("SUCCESS: Retrieved access token correctly!\n", .{});
        std.debug.print("  Token: {s}\n", .{token.token});
        std.debug.print("  Client ID: {s}\n", .{token.client_id});
        std.debug.print("  Scope: {s}\n", .{token.scope});
        
        if (token.refresh_token) |rt| {
            std.debug.print("  Refresh Token: {s}\n", .{rt});
            if (std.mem.eql(u8, rt, "refresh-token-123")) {
                std.debug.print("✅ CORRUPTION FIXED: Refresh token matches expected value!\n", .{});
            } else {
                std.debug.print("❌ CORRUPTION STILL EXISTS: Expected 'refresh-token-123', got '{s}'\n", .{rt});
            }
        } else {
            std.debug.print("❌ ERROR: Refresh token is null!\n", .{});
        }
    } else {
        std.debug.print("❌ ERROR: Could not retrieve access token!\n", .{});
    }

    // Test retrieving by refresh token
    std.debug.print("\nTesting retrieval by refresh token...\n", .{});
    const token_by_refresh = try db.getAccessTokenByRefresh("refresh-token-123");
    
    if (token_by_refresh) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        std.debug.print("✅ SUCCESS: Retrieved token by refresh token!\n", .{});
        std.debug.print("  Access Token: {s}\n", .{token.token});
    } else {
        std.debug.print("❌ ERROR: Could not retrieve token by refresh token!\n", .{});
    }
}