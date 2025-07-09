//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len > 1 and std.mem.eql(u8, args[1], "server")) {
        // Start HTTP server
        const config = server.ServerConfig{
            .host = "127.0.0.1",
            .port = 8080,
            .base_domain = "maigo.dev",
            .db_path = "maigo.db",
        };
        
        var http_server = try server.Server.init(allocator, config);
        defer http_server.deinit();
        try http_server.start();
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "create-client")) {
        // Create OAuth client
        if (args.len < 4) {
            std.debug.print("Usage: maigo create-client <name> <redirect_uri>\n", .{});
            return;
        }
        
        const name = args[2];
        const redirect_uri = args[3];
        
        var db = try database.Database.init(allocator, "maigo.db");
        defer db.deinit();
        
        var oauth_server = oauth.OAuthServer.init(allocator, &db);
        var client = try oauth_server.createClient(name, redirect_uri);
        defer client.deinit(allocator);
        
        // Store client in database
        try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
        
        std.debug.print("OAuth client created successfully:\n", .{});
        std.debug.print("Client ID: {s}\n", .{client.id});
        std.debug.print("Client Secret: {s}\n", .{client.secret});
        std.debug.print("Name: {s}\n", .{client.name});
        std.debug.print("Redirect URI: {s}\n", .{client.redirect_uri});
    } else {
        // Demo mode
        const stdout_file = std.io.getStdOut().writer();
        var bw = std.io.bufferedWriter(stdout_file);
        const stdout = bw.writer();

        try stdout.print("Maigo - Wildcard Subdomain URL Shortener\n", .{});
        try stdout.print("Version: 0.1.0\n", .{});
        try stdout.print("\nUsage:\n", .{});
        try stdout.print("  maigo server                        - Start HTTP server\n", .{});
        try stdout.print("  maigo create-client <name> <uri>    - Create OAuth client\n", .{});
        try stdout.print("  maigo                               - Show this demo\n", .{});
        
        // Demo shortener functionality
        var url_shortener = shortener.Shortener.init(allocator);
        
        // Test encoding
        var code = try url_shortener.encodeId(12345);
        defer code.deinit();
        try stdout.print("\nDemo - Encoded ID 12345: {s}\n", .{code.code});
        
        // Test decoding
        const decoded = try shortener.Shortener.decodeId(code.code);
        try stdout.print("Demo - Decoded back: {d}\n", .{decoded});
        
        // Test random generation
        var random_code = try url_shortener.generateRandom(6);
        defer random_code.deinit();
        try stdout.print("Demo - Random 6-char code: {s}\n", .{random_code.code});

        try bw.flush();
    }
}

test "simple test" {
    var list = std.ArrayList(i32).init(std.testing.allocator);
    defer list.deinit();
    try list.append(42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "maigo version" {
    const version = "0.1.0";
    try std.testing.expectEqualStrings("0.1.0", version);
}

test "use other module" {
    try std.testing.expectEqual(@as(i32, 150), lib.add(100, 50));
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            // Try passing `--fuzz` to `zig build test` and see if it manages to fail this test case!
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}

const std = @import("std");

/// This imports the separate module containing `root.zig`. Take a look in `build.zig` for details.
const lib = @import("maigo_lib");
const shortener = lib.shortener;
const server = lib.server;
const database = lib.database;
const oauth = lib.oauth;
