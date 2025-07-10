const std = @import("std");
const database = @import("src/database.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== MINIMAL DATABASE CORRUPTION TEST ===\n", .{});

    // Test: Only initialize database and create access token, no other operations
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();

    std.debug.print("✅ Database initialized\n", .{});

    // Manually create a minimal client entry to satisfy foreign key constraints
    try db.insertOAuthClient("test-client", "test-secret", "Test Client", "http://localhost");
    
    // Create a minimal user
    const user_id = try db.insertUser("testuser", "test@example.com", "password");
    
    std.debug.print("✅ Prerequisites created\n", .{});

    // The critical test: insert and retrieve access token
    const now = std.time.timestamp();
    const expires_at = now + 3600;
    
    std.debug.print("Inserting access token...\n", .{});
    try db.insertAccessToken("test-token", "test-client", user_id, "test-scope", expires_at, "test-refresh");

    std.debug.print("Retrieving access token...\n", .{});
    const result = try db.getAccessToken("test-token");
    
    if (result) |token| {
        defer {
            allocator.free(token.token);
            allocator.free(token.client_id);
            allocator.free(token.scope);
            if (token.refresh_token) |rt| {
                allocator.free(rt);
            }
        }
        
        std.debug.print("Token: '{s}'\n", .{token.token});
        std.debug.print("Client ID: '{s}'\n", .{token.client_id});
        std.debug.print("Scope: '{s}'\n", .{token.scope});
        
        if (token.refresh_token) |rt| {
            std.debug.print("Refresh Token: '{s}'\n", .{rt});
            std.debug.print("Refresh Token Length: {d}\n", .{rt.len});
            
            // Character-by-character analysis
            std.debug.print("Character analysis:\n", .{});
            for (rt, 0..) |char, i| {
                std.debug.print("  [{d}]: {} ({})\n", .{i, char, @as(u8, char)});
                if (i >= 20) break; // Limit output
            }
            
            if (std.mem.eql(u8, rt, "test-refresh")) {
                std.debug.print("✅ SUCCESS: Refresh token matches!\n", .{});
            } else {
                std.debug.print("❌ CORRUPTION: Expected 'test-refresh', got something else\n", .{});
            }
        } else {
            std.debug.print("❌ ERROR: Refresh token is null\n", .{});
        }
    } else {
        std.debug.print("❌ ERROR: Could not retrieve token\n", .{});
    }
}