const std = @import("std");

const TOKEN_PATH = "/Users/yukai/.maigo_tokens.json"; // TODO: use home dir dynamically
const AUTH_URL = "http://127.0.0.1:8080/oauth/authorize";
const TOKEN_URL = "http://127.0.0.1:8080/oauth/token";
const CLIENT_ID = "cli-demo"; // TODO: register and use real client_id
const CLIENT_SECRET = "cli-secret"; // TODO: register and use real secret
const REDIRECT_URI = "urn:ietf:wg:oauth:2.0:oob";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Step 1: Try to load tokens from disk
    var tokens = try loadTokens(allocator);
    defer if (tokens) |*t| t.deinit(allocator);

    if (tokens) |t| {
        if (!isExpired(t)) {
            std.debug.print("Already authenticated! Access token: {s}\n", .{t.access_token});
            return;
        } else if (t.refresh_token) |refresh| {
            std.debug.print("Access token expired, refreshing...\n", .{});
                const maybe_tokens = try refreshTokens(allocator, refresh);
                if (maybe_tokens) |nt| {
                    var new_tokens = nt;
                    try saveTokens(new_tokens);
                    std.debug.print("Refreshed! New access token: {s}\n", .{new_tokens.access_token});
                    new_tokens.deinit(allocator);
                    return;
                } else {
                    std.debug.print("Refresh failed, need to re-authenticate.\n", .{});
                }
        }
    }

    // Step 2: Start OOB Authorization Code Grant
    const url = try std.fmt.allocPrint(allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}&scope=url:read url:write",
        .{AUTH_URL, CLIENT_ID, REDIRECT_URI});
    defer allocator.free(url);

    std.debug.print("Please open the following URL in your browser and log in:\n{s}\n", .{url});
    std.debug.print("After authorizing, paste the code here: ", .{});

    var code_buf: [128]u8 = undefined;
    const code = try std.io.getStdIn().reader().readUntilDelimiterOrEof(&code_buf, '\n');
    if (code == null or code.?.len == 0) {
        std.debug.print("No code entered. Exiting.\n", .{});
        return;
    }

    // Step 3: Exchange code for tokens
        const maybe_tokens = try exchangeCodeForTokens(allocator, code.?);
        if (maybe_tokens) |nt| {
            var new_tokens = nt;
            try saveTokens(new_tokens);
            std.debug.print("Authenticated! Access token: {s}\n", .{new_tokens.access_token});
            new_tokens.deinit(allocator);
        } else {
            std.debug.print("Failed to authenticate.\n", .{});
        }
}

const TokenSet = struct {
    access_token: []u8,
    refresh_token: ?[]u8,
    expires_at: i64,

    fn deinit(self: *TokenSet, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |rt| allocator.free(rt);
    }
};

fn loadTokens(allocator: std.mem.Allocator) !?TokenSet {
    var file = std.fs.cwd().openFile(TOKEN_PATH, .{}) catch return null;
    defer file.close();
    var buf: [512]u8 = undefined;
    const n = try file.readAll(&buf);
    const json = buf[0..n];
    // Very simple JSON parsing (not robust)
    var access_token_iter = std.mem.tokenizeSequence(u8, json, "\"access_token\":\"");
    const access_token = access_token_iter.next() orelse return null;
    var access_token_val_iter = std.mem.tokenizeSequence(u8, access_token, "\"");
    const access_token_val = access_token_val_iter.next() orelse return null;
    var refresh_token_iter = std.mem.tokenizeSequence(u8, json, "\"refresh_token\":\"");
    const refresh_token = refresh_token_iter.next();
    const refresh_token_val = if (refresh_token) |rt| blk: {
        var rt_iter = std.mem.tokenizeSequence(u8, rt, "\"");
        break :blk rt_iter.next();
    } else null;
    var expires_at_iter = std.mem.tokenizeSequence(u8, json, "\"expires_at\":");
    const expires_at = expires_at_iter.next() orelse return null;
    const expires_at_val = std.fmt.parseInt(i64, std.mem.trim(u8, expires_at, ",} \n"), 10) catch return null;
    return TokenSet{
        .access_token = try allocator.dupe(u8, access_token_val),
        .refresh_token = if (refresh_token_val) |rt| try allocator.dupe(u8, rt) else null,
        .expires_at = expires_at_val,
    };
}

fn saveTokens(tokens: TokenSet) !void {
    var file = try std.fs.cwd().createFile(TOKEN_PATH, .{ .truncate = true });
    defer file.close();
    const refresh = if (tokens.refresh_token) |rt| rt else "";
    const json = try std.fmt.allocPrint(std.heap.page_allocator,
        "{{\"access_token\":\"{s}\",\"refresh_token\":\"{s}\",\"expires_at\":{d}}}",
        .{tokens.access_token, refresh, tokens.expires_at});
    defer std.heap.page_allocator.free(json);
    _ = try file.writeAll(json);
}

fn isExpired(tokens: TokenSet) bool {
    return std.time.timestamp() > tokens.expires_at - 60; // 1 min leeway
}

fn exchangeCodeForTokens(allocator: std.mem.Allocator, code: []const u8) !?TokenSet {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const body = try std.fmt.allocPrint(allocator,
        "grant_type=authorization_code&client_id={s}&client_secret={s}&code={s}&redirect_uri={s}",
        .{CLIENT_ID, CLIENT_SECRET, code, REDIRECT_URI});
    defer allocator.free(body);

    const token_uri = try std.Uri.parse(TOKEN_URL);
    const headers_arr = [_]std.http.Header{
        std.http.Header{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
    };
    var header_buf: [512]u8 = undefined;
    var req = try client.open(.POST, token_uri, .{
        .extra_headers = headers_arr[0..],
        .server_header_buffer = &header_buf,
    });
    defer req.deinit();
    try req.writeAll(body);
    try req.finish();

    if (req.response.status != .ok) {
        std.debug.print("Token endpoint returned status: {d}\n", .{@intFromEnum(req.response.status)});
        return null;
    }

    var resp_buf: [1024]u8 = undefined;
    const n = try req.readAll(&resp_buf);
    const resp = resp_buf[0..n];
    // Parse JSON (very simple, not robust)
    var access_token_iter = std.mem.tokenizeSequence(u8, resp, "\"access_token\":\"");
    const access_token = access_token_iter.next() orelse return null;
    var access_token_val_iter = std.mem.tokenizeSequence(u8, access_token, "\"");
    const access_token_val = access_token_val_iter.next() orelse return null;
    var refresh_token_iter = std.mem.tokenizeSequence(u8, resp, "\"refresh_token\":\"");
    const refresh_token = refresh_token_iter.next();
    const refresh_token_val = if (refresh_token) |rt| blk: {
        var rt_iter = std.mem.tokenizeSequence(u8, rt, "\"");
        break :blk rt_iter.next();
    } else null;
    var expires_in_iter = std.mem.tokenizeSequence(u8, resp, "\"expires_in\":");
    const expires_in = expires_in_iter.next() orelse return null;
    const expires_in_val = std.fmt.parseInt(i64, std.mem.trim(u8, expires_in, ",} \n"), 10) catch return null;
    const expires_at = std.time.timestamp() + expires_in_val;
    return TokenSet{
        .access_token = try allocator.dupe(u8, access_token_val),
        .refresh_token = if (refresh_token_val) |rt| try allocator.dupe(u8, rt) else null,
        .expires_at = expires_at,
    };
}

fn refreshTokens(allocator: std.mem.Allocator, refresh_token: []const u8) !?TokenSet {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const body = try std.fmt.allocPrint(allocator,
        "grant_type=refresh_token&client_id={s}&client_secret={s}&refresh_token={s}",
        .{CLIENT_ID, CLIENT_SECRET, refresh_token});
    defer allocator.free(body);

    const token_uri = try std.Uri.parse(TOKEN_URL);
    const headers_arr = [_]std.http.Header{
        std.http.Header{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
    };
    var header_buf: [512]u8 = undefined;
    var req = try client.open(.POST, token_uri, .{
        .extra_headers = headers_arr[0..],
        .server_header_buffer = &header_buf,
    });
    defer req.deinit();
    try req.writeAll(body);
    try req.finish();

    if (req.response.status != .ok) {
        std.debug.print("Token endpoint returned status: {d}\n", .{@intFromEnum(req.response.status)});
        return null;
    }

    var resp_buf: [1024]u8 = undefined;
    const n = try req.readAll(&resp_buf);
    const resp = resp_buf[0..n];
    // Parse JSON (very simple, not robust)
    var access_token_iter = std.mem.tokenizeSequence(u8, resp, "\"access_token\":\"");
    const access_token = access_token_iter.next() orelse return null;
    var access_token_val_iter = std.mem.tokenizeSequence(u8, access_token, "\"");
    const access_token_val = access_token_val_iter.next() orelse return null;
    var refresh_token_iter = std.mem.tokenizeSequence(u8, resp, "\"refresh_token\":\"");
    const refresh_token2 = refresh_token_iter.next();
    const refresh_token_val2 = if (refresh_token2) |rt| blk: {
        var rt_iter = std.mem.tokenizeSequence(u8, rt, "\"");
        break :blk rt_iter.next();
    } else null;
    var expires_in_iter = std.mem.tokenizeSequence(u8, resp, "\"expires_in\":");
    const expires_in = expires_in_iter.next() orelse return null;
    const expires_in_val = std.fmt.parseInt(i64, std.mem.trim(u8, expires_in, ",} \n"), 10) catch return null;
    const expires_at = std.time.timestamp() + expires_in_val;
    return TokenSet{
        .access_token = try allocator.dupe(u8, access_token_val),
        .refresh_token = if (refresh_token_val2) |rt| try allocator.dupe(u8, rt) else null,
        .expires_at = expires_at,
    };
}
