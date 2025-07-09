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

        // Initialize database (CLI client fixture is automatically created)
        var db = try database.Database.init(allocator, config.db_path);
        defer db.deinit();

        // Create CLI client credentials file for convenience
        try ensureCliClientFile(allocator);

        var http_server = try server.Server.init(allocator, config);
        defer http_server.deinit();
        try http_server.start();
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "ssh-server")) {
        // Start libssh server (recommended)
        const config = server.ServerConfig{
            .host = "127.0.0.1",
            .port = 8080,
            .base_domain = "maigo.dev",
            .db_path = "maigo.db",
        };

        var db = try database.Database.init(allocator, config.db_path);
        defer db.deinit();

        var ssh_srv = try libssh_server.LibSSHServer.init(allocator, &db, "127.0.0.1", 2222);
        defer ssh_srv.deinit();
        try ssh_srv.start();
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
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "login")) {
        // CLI user login
        try handleCliLogin(allocator);
    } else if (args.len > 1 and std.mem.eql(u8, args[1], "auth")) {
        // CLI OAuth authentication helper
        if (args.len > 2 and std.mem.eql(u8, args[2], "url")) {
            try printAuthUrl(allocator);
        } else if (args.len > 3 and std.mem.eql(u8, args[2], "token")) {
            const auth_code = args[3];
            try exchangeAuthCode(allocator, auth_code);
        } else if (args.len > 2 and std.mem.eql(u8, args[2], "status")) {
            try showAuthStatus(allocator);
        } else {
            std.debug.print("Usage:\n", .{});
            std.debug.print("  maigo auth url              - Get authorization URL\n", .{});
            std.debug.print("  maigo auth token <code>     - Exchange auth code for token\n", .{});
            std.debug.print("  maigo auth status           - Show authentication status\n", .{});
        }
    } else if (args.len > 2 and std.mem.eql(u8, args[1], "shorten")) {
        // Create short URL using CLI
        const target_url = args[2];
        try createShortUrl(allocator, target_url);
    } else {
        // Demo mode
        const stdout_file = std.io.getStdOut().writer();
        var bw = std.io.bufferedWriter(stdout_file);
        const stdout = bw.writer();

        try stdout.print("Maigo - Wildcard Subdomain URL Shortener\n", .{});
        try stdout.print("Version: 0.1.0\n", .{});
        try stdout.print("\nUsage:\n", .{});
        try stdout.print("  maigo server                        - Start HTTP server\n", .{});
        try stdout.print("  maigo ssh-server                    - Start SSH server for registration\n", .{});
        try stdout.print("  maigo login                         - Login with username/password\n", .{});
        try stdout.print("  maigo auth url                      - Get CLI authorization URL\n", .{});
        try stdout.print("  maigo auth token <code>             - Exchange auth code for token\n", .{});
        try stdout.print("  maigo auth status                   - Show authentication status\n", .{});
        try stdout.print("  maigo shorten <url>                 - Create short URL\n", .{});
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
const libssh_server = lib.libssh_server;

const CLI_CLIENT_FILE = "maigo-cli.json";

fn ensureCliClientFile(allocator: std.mem.Allocator) !void {
    // Get CLI client credentials from database fixture
    const cli_creds = database.getCliClientCredentials();

    // Save client credentials to file for CLI use
    const client_json = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "client_id": "{s}",
        \\  "client_secret": "{s}",
        \\  "redirect_uri": "{s}",
        \\  "token_endpoint": "http://127.0.0.1:8080/oauth/token",
        \\  "authorization_endpoint": "http://127.0.0.1:8080/oauth/authorize"
        \\}}
    , .{ cli_creds.client_id, cli_creds.client_secret, cli_creds.redirect_uri });
    defer allocator.free(client_json);

    const file = std.fs.cwd().createFile(CLI_CLIENT_FILE, .{}) catch |err| {
        std.debug.print("Warning: Could not create CLI client file: {}\n", .{err});
        return;
    };
    defer file.close();

    try file.writeAll(client_json);

    std.debug.print("CLI client credentials file created: {s}\n", .{CLI_CLIENT_FILE});
    std.debug.print("Client ID: {s}\n", .{cli_creds.client_id});
}

fn printAuthUrl(allocator: std.mem.Allocator) !void {
    // Get CLI client credentials from fixture
    const cli_creds = database.getCliClientCredentials();

    const auth_url = try std.fmt.allocPrint(allocator, "http://127.0.0.1:8080/oauth/authorize?response_type=code&client_id={s}&redirect_uri={s}&scope=url:read%20url:write", .{ cli_creds.client_id, cli_creds.redirect_uri });
    defer allocator.free(auth_url);

    std.debug.print("Open this URL in your browser to authorize the CLI:\n\n{s}\n\n", .{auth_url});
    std.debug.print("After authorization, copy the authorization code and run:\n", .{});
    std.debug.print("  maigo auth token <authorization_code>\n", .{});
}

fn exchangeAuthCode(allocator: std.mem.Allocator, auth_code: []const u8) !void {
    // Get CLI client credentials from fixture
    const cli_creds = database.getCliClientCredentials();

    std.debug.print("Exchanging authorization code for access token...\n", .{});

    // For now, show manual steps and provide a way to save the token
    std.debug.print("Make this POST request to get your access token:\n\n", .{});
    std.debug.print("curl -X POST http://127.0.0.1:8080/oauth/token \\\n", .{});
    std.debug.print("  -d 'grant_type=authorization_code' \\\n", .{});
    std.debug.print("  -d 'client_id={s}' \\\n", .{cli_creds.client_id});
    std.debug.print("  -d 'client_secret={s}' \\\n", .{cli_creds.client_secret});
    std.debug.print("  -d 'code={s}' \\\n", .{auth_code});
    std.debug.print("  -d 'redirect_uri={s}'\n\n", .{cli_creds.redirect_uri});

    std.debug.print("After running the curl command, you'll get a JSON response like:\n", .{});
    std.debug.print("{{\"access_token\":\"your_token_here\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"refresh_token\":\"refresh_token_here\",\"scope\":\"url:read url:write\"}}\n\n", .{});

    // Ask user to paste the access token
    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    try stdout.print("Paste the access_token value here: ", .{});
    var token_buffer: [1024]u8 = undefined;
    if (try stdin.readUntilDelimiterOrEof(&token_buffer, '\n')) |input| {
        const access_token = std.mem.trim(u8, input, " \r\n\t\"");

        if (access_token.len > 0) {
            try saveAccessToken(allocator, access_token);
            std.debug.print("Access token saved! You can now use 'maigo shorten <url>' to create short URLs.\n", .{});
        } else {
            std.debug.print("No token provided. Please run the command again.\n", .{});
        }
    }
}

fn saveAccessToken(allocator: std.mem.Allocator, access_token: []const u8) !void {
    // Load existing session data
    const home_dir = std.posix.getenv("HOME") orelse ".";
    const data_path = try std.fmt.allocPrint(allocator, "{s}/.config/maigo/data.json", .{home_dir});
    defer allocator.free(data_path);

    const existing_data = std.fs.cwd().readFileAlloc(allocator, data_path, 4096) catch |err| {
        switch (err) {
            error.FileNotFound => {
                std.debug.print("No session found. Please run 'maigo login' first.\n", .{});
                return;
            },
            else => return err,
        }
    };
    defer allocator.free(existing_data);

    // Parse existing user data
    const user_id = parseJsonValue(allocator, existing_data, "user_id") catch {
        std.debug.print("Invalid session data. Please run 'maigo login' again.\n", .{});
        return;
    };
    defer allocator.free(user_id);

    const username = parseJsonValue(allocator, existing_data, "username") catch {
        std.debug.print("Invalid session data. Please run 'maigo login' again.\n", .{});
        return;
    };
    defer allocator.free(username);

    // Create updated session data with access token
    const updated_data = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "user_id": {s},
        \\  "username": "{s}",
        \\  "access_token": "{s}",
        \\  "logged_in_at": {d},
        \\  "token_saved_at": {d}
        \\}}
    , .{ user_id, username, access_token, std.time.timestamp() - 3600, std.time.timestamp() });
    defer allocator.free(updated_data);

    const file = try std.fs.createFileAbsolute(data_path, .{});
    defer file.close();

    try file.writeAll(updated_data);

    std.debug.print("Access token saved to: {s}\n", .{data_path});
}

fn handleCliLogin(allocator: std.mem.Allocator) !void {
    const stdin = std.io.getStdIn().reader();
    const stdout = std.io.getStdOut().writer();

    try stdout.print("Maigo CLI Login\n", .{});
    try stdout.print("===============\n\n", .{});

    // Get username
    try stdout.print("Username: ", .{});
    var username_buffer: [256]u8 = undefined;
    if (try stdin.readUntilDelimiterOrEof(&username_buffer, '\n')) |input| {
        const username = std.mem.trim(u8, input, " \r\n\t");

        if (username.len == 0) {
            try stdout.print("Username cannot be empty.\n", .{});
            return;
        }

        // Get password (note: this will be visible, in production use proper password masking)
        try stdout.print("Password: ", .{});
        var password_buffer: [256]u8 = undefined;
        if (try stdin.readUntilDelimiterOrEof(&password_buffer, '\n')) |pass_input| {
            const password = std.mem.trim(u8, pass_input, " \r\n\t");

            // Verify credentials with database
            var db = try database.Database.init(allocator, "maigo.db");
            defer db.deinit();

            const user = try db.getUserByUsername(username);
            if (user == null) {
                try stdout.print("Invalid username or password.\n", .{});
                return;
            }

            var authenticated_user = user.?;
            defer authenticated_user.deinit(allocator);

            // Hash password and compare
            const password_hash = try hashPassword(allocator, password);
            defer allocator.free(password_hash);

            if (!std.mem.eql(u8, authenticated_user.password_hash, password_hash)) {
                try stdout.print("Invalid username or password.\n", .{});
                return;
            }

            try stdout.print("Login successful! Welcome, {s}!\n\n", .{authenticated_user.username});

            // Save user session
            try saveUserSession(allocator, authenticated_user.id, authenticated_user.username);

            try stdout.print("Next steps:\n", .{});
            try stdout.print("1. Run 'maigo auth url' to get authorization URL\n", .{});
            try stdout.print("2. Open URL in browser and authorize\n", .{});
            try stdout.print("3. Run 'maigo auth token <code>' to get access token\n", .{});
            try stdout.print("4. Start creating short URLs!\n", .{});
        }
    }
}

fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    // Same hashing logic as SSH TUI
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("maigo_salt_");
    hasher.update(password);

    var hash_bytes: [32]u8 = undefined;
    hasher.final(&hash_bytes);

    const hex_chars = "0123456789abcdef";
    var hex_string = try allocator.alloc(u8, 64);
    for (hash_bytes, 0..) |byte, i| {
        hex_string[i * 2] = hex_chars[byte >> 4];
        hex_string[i * 2 + 1] = hex_chars[byte & 0xf];
    }

    return hex_string;
}

fn saveUserSession(allocator: std.mem.Allocator, user_id: u64, username: []const u8) !void {
    // Create ~/.config/maigo directory
    const home_dir = std.posix.getenv("HOME") orelse ".";
    const config_dir = try std.fmt.allocPrint(allocator, "{s}/.config/maigo", .{home_dir});
    defer allocator.free(config_dir);

    std.fs.makeDirAbsolute(config_dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const data_path = try std.fmt.allocPrint(allocator, "{s}/data.json", .{config_dir});
    defer allocator.free(data_path);

    const session_data = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "user_id": {d},
        \\  "username": "{s}",
        \\  "logged_in_at": {d}
        \\}}
    , .{ user_id, username, std.time.timestamp() });
    defer allocator.free(session_data);

    const file = try std.fs.createFileAbsolute(data_path, .{});
    defer file.close();

    try file.writeAll(session_data);

    std.debug.print("Session saved to: {s}\n", .{data_path});
}

fn showAuthStatus(allocator: std.mem.Allocator) !void {
    const home_dir = std.posix.getenv("HOME") orelse ".";
    const data_path = try std.fmt.allocPrint(allocator, "{s}/.config/maigo/data.json", .{home_dir});
    defer allocator.free(data_path);

    const data_content = std.fs.cwd().readFileAlloc(allocator, data_path, 4096) catch |err| {
        switch (err) {
            error.FileNotFound => {
                std.debug.print("Not logged in. Run 'maigo login' first.\n", .{});
                return;
            },
            else => return err,
        }
    };
    defer allocator.free(data_content);

    std.debug.print("Authentication Status:\n", .{});
    std.debug.print("======================\n", .{});
    std.debug.print("Session data: {s}\n\n", .{data_content});

    // Check if access token exists
    const access_token = parseJsonValue(allocator, data_content, "access_token") catch null;
    if (access_token) |token| {
        defer allocator.free(token);
        std.debug.print("Access token: {s}...{s}\n", .{ token[0..8], token[token.len - 8 ..] });
        std.debug.print("Status: Authenticated ✓\n", .{});
    } else {
        std.debug.print("Status: Logged in, but no OAuth token\n", .{});
        std.debug.print("Run 'maigo auth url' to get authorization URL\n", .{});
    }
}

fn createShortUrl(allocator: std.mem.Allocator, target_url: []const u8) !void {
    // Load user session and access token
    const home_dir = std.posix.getenv("HOME") orelse ".";
    const data_path = try std.fmt.allocPrint(allocator, "{s}/.config/maigo/data.json", .{home_dir});
    defer allocator.free(data_path);

    const data_content = std.fs.cwd().readFileAlloc(allocator, data_path, 4096) catch |err| {
        switch (err) {
            error.FileNotFound => {
                std.debug.print("Not logged in. Run 'maigo login' first.\n", .{});
                return;
            },
            else => return err,
        }
    };
    defer allocator.free(data_content);

    const access_token = parseJsonValue(allocator, data_content, "access_token") catch |err| {
        switch (err) {
            error.KeyNotFound => {
                std.debug.print("No access token found. Complete OAuth flow first:\n", .{});
                std.debug.print("1. Run 'maigo auth url'\n", .{});
                std.debug.print("2. Open URL and authorize\n", .{});
                std.debug.print("3. Run 'maigo auth token <code>'\n", .{});
                return;
            },
            else => return err,
        }
    };
    defer allocator.free(access_token);

    std.debug.print("Creating short URL for: {s}\n", .{target_url});
    std.debug.print("Using access token: {s}...{s}\n", .{ access_token[0..8], access_token[access_token.len - 8 ..] });

    // TODO: Make authenticated HTTP request to /api/urls
    std.debug.print("\nTo create the short URL manually, use this curl command:\n", .{});
    std.debug.print("curl -X POST http://127.0.0.1:8080/api/urls \\\n", .{});
    std.debug.print("  -H 'Authorization: Bearer {s}' \\\n", .{access_token});
    std.debug.print("  -H 'Content-Type: application/json' \\\n", .{});
    std.debug.print("  -d '{{\"url\":\"{s}\"}}'\n", .{target_url});
}

fn parseJsonValue(allocator: std.mem.Allocator, json: []const u8, key: []const u8) ![]u8 {
    const key_prefix = try std.fmt.allocPrint(allocator, "\"{s}\": \"", .{key});
    defer allocator.free(key_prefix);

    const value_start_idx = std.mem.indexOf(u8, json, key_prefix) orelse return error.KeyNotFound;
    const value_start = value_start_idx + key_prefix.len;
    const value_end = std.mem.indexOfPos(u8, json, value_start, "\"") orelse return error.InvalidFormat;

    return allocator.dupe(u8, json[value_start..value_end]);
}
