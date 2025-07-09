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
        
        // Initialize database and create canonical CLI client if needed
        var db = try database.Database.init(allocator, config.db_path);
        defer db.deinit();
        
        var oauth_server = oauth.OAuthServer.init(allocator, &db);
        try ensureCliClient(allocator, &oauth_server, &db);
        
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
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "auth")) {
        // CLI OAuth authentication helper
        if (args.len > 2 and std.mem.eql(u8, args[2], "url")) {
            try printAuthUrl(allocator);
        } else if (args.len > 3 and std.mem.eql(u8, args[2], "token")) {
            const auth_code = args[3];
            try exchangeAuthCode(allocator, auth_code);
        } else {
            std.debug.print("Usage:\n", .{});
            std.debug.print("  maigo auth url              - Get authorization URL\n", .{});
            std.debug.print("  maigo auth token <code>     - Exchange auth code for token\n", .{});
        }
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
        try stdout.print("  maigo auth url                      - Get CLI authorization URL\n", .{});
        try stdout.print("  maigo auth token <code>             - Exchange auth code for token\n", .{});
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

const CLI_CLIENT_ID = "maigo-cli";
const CLI_CLIENT_NAME = "Maigo CLI";
const CLI_CLIENT_REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob"; // out-of-band
const CLI_CLIENT_FILE = "maigo-cli.json";

fn ensureCliClient(allocator: std.mem.Allocator, oauth_server: *oauth.OAuthServer, db: *database.Database) !void {
    // Check if CLI client already exists
    const existing_client = db.getOAuthClient(CLI_CLIENT_ID) catch |err| switch (err) {
        database.DatabaseError.PrepareFailed, database.DatabaseError.StepFailed => return err,
        else => null,
    };
    
    if (existing_client) |client_data| {
        // Client exists, clean up allocated data
        allocator.free(client_data.id);
        allocator.free(client_data.secret);
        allocator.free(client_data.name);
        allocator.free(client_data.redirect_uri);
        std.debug.print("CLI OAuth client already exists\n", .{});
        return;
    }
    
    // Create new CLI client
    std.debug.print("Creating canonical CLI OAuth client...\n", .{});
    
    var client = try oauth_server.createClient(CLI_CLIENT_NAME, CLI_CLIENT_REDIRECT_URI);
    defer client.deinit(allocator);
    
    // Use fixed client ID for CLI
    allocator.free(client.id);
    client.id = try allocator.dupe(u8, CLI_CLIENT_ID);
    
    // Store client in database
    try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
    
    // Save client credentials to file for CLI use
    const client_json = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "client_id": "{s}",
        \\  "client_secret": "{s}",
        \\  "redirect_uri": "{s}",
        \\  "token_endpoint": "http://127.0.0.1:8080/oauth/token",
        \\  "authorization_endpoint": "http://127.0.0.1:8080/oauth/authorize"
        \\}}
    , .{ client.id, client.secret, client.redirect_uri });
    defer allocator.free(client_json);
    
    const file = std.fs.cwd().createFile(CLI_CLIENT_FILE, .{}) catch |err| {
        std.debug.print("Warning: Could not create CLI client file: {}\n", .{err});
        return;
    };
    defer file.close();
    
    try file.writeAll(client_json);
    
    std.debug.print("CLI OAuth client created successfully!\n", .{});
    std.debug.print("Client credentials saved to: {s}\n", .{CLI_CLIENT_FILE});
    std.debug.print("Client ID: {s}\n", .{client.id});
}

fn printAuthUrl(allocator: std.mem.Allocator) !void {
    // Read CLI client credentials
    const client_json = std.fs.cwd().readFileAlloc(allocator, CLI_CLIENT_FILE, 1024) catch |err| {
        std.debug.print("Error: Could not read CLI client file '{s}': {}\n", .{ CLI_CLIENT_FILE, err });
        std.debug.print("Please run 'maigo server' first to create the CLI client.\n", .{});
        return;
    };
    defer allocator.free(client_json);
    
    // Simple JSON parsing for client_id
    const client_id_prefix = "\"client_id\": \"";
    const client_id_start = std.mem.indexOf(u8, client_json, client_id_prefix) orelse {
        std.debug.print("Error: Invalid client file format\n", .{});
        return;
    };
    const id_start = client_id_start + client_id_prefix.len;
    const id_end = std.mem.indexOfPos(u8, client_json, id_start, "\"") orelse {
        std.debug.print("Error: Invalid client file format\n", .{});
        return;
    };
    const client_id = client_json[id_start..id_end];
    
    const auth_url = try std.fmt.allocPrint(allocator,
        "http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id={s}&redirect_uri={s}&scope=url:read%20url:write",
        .{ client_id, CLI_CLIENT_REDIRECT_URI }
    );
    defer allocator.free(auth_url);
    
    std.debug.print("Open this URL in your browser to authorize the CLI:\n\n{s}\n\n", .{auth_url});
    std.debug.print("After authorization, copy the authorization code and run:\n", .{});
    std.debug.print("  maigo auth token <authorization_code>\n", .{});
}

fn exchangeAuthCode(allocator: std.mem.Allocator, auth_code: []const u8) !void {
    // Read CLI client credentials
    const client_json = std.fs.cwd().readFileAlloc(allocator, CLI_CLIENT_FILE, 1024) catch |err| {
        std.debug.print("Error: Could not read CLI client file '{s}': {}\n", .{ CLI_CLIENT_FILE, err });
        std.debug.print("Please run 'maigo server' first to create the CLI client.\n", .{});
        return;
    };
    defer allocator.free(client_json);
    
    // Parse client_id and client_secret
    const client_id = try parseJsonValue(allocator, client_json, "client_id");
    defer allocator.free(client_id);
    
    const client_secret = try parseJsonValue(allocator, client_json, "client_secret");
    defer allocator.free(client_secret);
    
    // Make HTTP request to token endpoint
    // For now, just show what the user should do manually
    std.debug.print("To exchange the authorization code for a token, make a POST request to:\n", .{});
    std.debug.print("URL: http://127.0.0.1:8080/oauth/token\n", .{});
    std.debug.print("Body: grant_type=authorization_code&client_id={s}&client_secret={s}&code={s}&redirect_uri={s}\n", 
        .{ client_id, client_secret, auth_code, CLI_CLIENT_REDIRECT_URI });
    std.debug.print("\nExample curl command:\n", .{});
    std.debug.print("curl -X POST http://127.0.0.1:8080/oauth/token \\\n", .{});
    std.debug.print("  -d 'grant_type=authorization_code' \\\n", .{});
    std.debug.print("  -d 'client_id={s}' \\\n", .{client_id});
    std.debug.print("  -d 'client_secret={s}' \\\n", .{client_secret});
    std.debug.print("  -d 'code={s}' \\\n", .{auth_code});
    std.debug.print("  -d 'redirect_uri={s}'\n", .{CLI_CLIENT_REDIRECT_URI});
}

fn parseJsonValue(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const key_prefix = try std.fmt.allocPrint(allocator, "\"{s}\": \"", .{key});
    defer allocator.free(key_prefix);
    
    const value_start_idx = std.mem.indexOf(u8, json, key_prefix) orelse return error.KeyNotFound;
    const value_start = value_start_idx + key_prefix.len;
    const value_end = std.mem.indexOfPos(u8, json, value_start, "\"") orelse return error.InvalidFormat;
    
    return allocator.dupe(u8, json[value_start..value_end]);
}
