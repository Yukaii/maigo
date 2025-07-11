const crypto = std.crypto;
// Session management
const SESSION_COOKIE_NAME = "maigo_session";
const SESSION_DURATION_SECS: i64 = 3600 * 24 * 7; // 1 week

fn generateSessionId(allocator: std.mem.Allocator) ![]u8 {
    var buf: [32]u8 = undefined;
    crypto.random.bytes(&buf);
    return std.fmt.allocPrint(allocator, "{s}", .{std.fmt.fmtSliceHexLower(&buf)});
}

// In-memory session store for demo (replace with DB for production)
var session_store = std.StringHashMap(u64).init(std.heap.page_allocator);

fn setSession(session_id: []const u8, user_id: u64) void {
    session_store.put(session_id, user_id) catch {};
}

fn getSession(session_id: []const u8) ?u64 {
    return session_store.get(session_id);
}

fn clearSession(session_id: []const u8) void {
    session_store.remove(session_id);
}
const std = @import("std");
const net = std.net;
const testing = std.testing;
const shortener = @import("shortener.zig");
const database_pg = @import("database_pg.zig");
const postgres = @import("postgres.zig");
const oauth = @import("oauth.zig");

pub const ServerConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    base_domain: []const u8 = "maigo.dev",
    db_path: []const u8 = "maigo.db",
};

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
    body: []const u8,
    authorization: ?[]const u8,

    pub fn parse(allocator: std.mem.Allocator, raw_request: []const u8) !HttpRequest {
        var lines = std.mem.splitSequence(u8, raw_request, "\r\n");

        // Parse request line
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitSequence(u8, request_line, " ");
        const method = parts.next() orelse return error.InvalidRequest;
        const path = parts.next() orelse return error.InvalidRequest;

        // Parse headers
        var host: []const u8 = "";
        var authorization: ?[]const u8 = null;
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line marks end of headers

            if (std.mem.startsWith(u8, line, "Host: ")) {
                host = line[6..];
            } else if (std.mem.startsWith(u8, line, "Authorization: ")) {
                authorization = try allocator.dupe(u8, line[15..]);
            }
        }

        // Get body (remaining content)
        const body = lines.rest();

        return HttpRequest{
            .method = try allocator.dupe(u8, method),
            .path = try allocator.dupe(u8, path),
            .host = try allocator.dupe(u8, host),
            .body = try allocator.dupe(u8, body),
            .authorization = authorization,
        };
    }

    pub fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        allocator.free(self.host);
        allocator.free(self.body);
        if (self.authorization) |auth| {
            allocator.free(auth);
        }
    }
};

pub const RouteHandler = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    url_shortener: shortener.Shortener,
    db: database_pg.Database,
    oauth_server: oauth.OAuthServer,

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !RouteHandler {
    // Update to use the new Postgres config and Database
    const pg_config: postgres.DatabaseConfig = .{
        .database = "maigo",
        .username = "postgres",
        .password = "password",
    }; // TODO: load from config if needed
    var db = try database_pg.Database.init(allocator, pg_config);

        return RouteHandler{
            .allocator = allocator,
            .config = config,
            .url_shortener = shortener.Shortener.init(allocator),
            .db = db,
            .oauth_server = oauth.OAuthServer.init(allocator, &db),
        };
    }

    pub fn deinit(self: *RouteHandler) void {
        self.db.deinit();
    }

    pub fn handleRequest(self: *RouteHandler, request: HttpRequest, writer: anytype) !void {
        std.debug.print("Request: {s} {s} Host: {s}\n", .{ request.method, request.path, request.host });

        // Parse subdomain from host
        const subdomain = try self.parseSubdomain(request.host);
        defer if (subdomain) |sub| self.allocator.free(sub);

        if (std.mem.eql(u8, request.method, "GET")) {
            if (std.mem.startsWith(u8, request.path, "/api/urls")) {
                try self.handleProtectedUrlsApi(writer, request);
            } else if (std.mem.startsWith(u8, request.path, "/oauth/authorize")) {
                try self.handleOAuthAuthorize(writer, request);
            } else if (std.mem.startsWith(u8, request.path, "/login")) {
                try self.handleLoginGet(writer, request);
            } else if (subdomain) |sub| {
                try self.handleRedirect(writer, sub);
            } else {
                try self.handleMainDomain(writer, request.path);
            }
        } else if (std.mem.eql(u8, request.method, "POST")) {
            if (std.mem.startsWith(u8, request.path, "/api/urls")) {
                try self.handleProtectedUrlsApi(writer, request);
            } else if (std.mem.eql(u8, request.path, "/api/shorten")) {
                try self.handleShorten(writer, request.body);
            } else if (std.mem.eql(u8, request.path, "/oauth/token")) {
                try self.handleOAuthToken(writer, request.body);
            } else if (std.mem.eql(u8, request.path, "/login")) {
                try self.handleLoginPost(writer, request);
            } else {
                try self.sendNotFound(writer);
            }
        } else {
            try self.sendMethodNotAllowed(writer);
        }
    }

    // Extract session_id from Cookie header
    fn getSessionIdFromRequest(request: HttpRequest) ?[]const u8 {
        // Look for "Cookie: maigo_session=..."
        const cookie_header = RouteHandler.getHeader(request, "Cookie");
        if (cookie_header) |cookie| {
            if (std.mem.indexOf(u8, cookie, SESSION_COOKIE_NAME ++ "=")) |idx| {
                const start = idx + SESSION_COOKIE_NAME.len + 1;
                const end = std.mem.indexOfPos(u8, cookie, start, ";") orelse cookie.len;
                return cookie[start..end];
            }
        }
        return null;
    }

    fn getHeader(unused_request: HttpRequest, unused_name: []const u8) ?[]const u8 {
        // Only Cookie is supported for now
        // Not implemented: always return null
        _ = unused_request;
        _ = unused_name;
        return null;

    }

    fn handleLoginGet(self: *RouteHandler, writer: anytype, request: HttpRequest) !void {
        // Show login form
        const return_to = self.parseQueryValue(request.path, "return_to") orelse "/";
            const html = try std.fmt.allocPrint(self.allocator,
                "<!DOCTYPE html><html><head><title>Login</title></head><body><h1>Login</h1><form method='post' action='/login'><input type='hidden' name='return_to' value=\"{s}\"><label>Username: <input name='username'></label><br><label>Password: <input type='password' name='password'></label><br><button type='submit'>Login</button></form></body></html>",
                .{return_to});
        defer self.allocator.free(html);
        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html });
        defer self.allocator.free(response);
        try writer.writeAll(response);
    }

    fn handleLoginPost(self: *RouteHandler, writer: anytype, request: HttpRequest) !void {
        // Parse form values
        const username = self.parseFormValue(request.body, "username") orelse {
            try self.sendBadRequest(writer, "Missing username");
            return;
        };
        const password = self.parseFormValue(request.body, "password") orelse {
            try self.sendBadRequest(writer, "Missing password");
            return;
        };
        const return_to = self.parseFormValue(request.body, "return_to") orelse "/";

        // Authenticate user
        const user = self.db.getUserByUsername(username) catch |err| {
            std.debug.print("DB error: {}\n", .{err});
            try self.sendInternalError(writer);
            return;
        };
        if (user == null) {
            try self.sendBadRequest(writer, "Invalid username or password");
            return;
        }
        var u = user.?;
        defer u.deinit(self.allocator);
        // Hash password and compare
        const password_hash = try hashPassword(self.allocator, password);
        defer self.allocator.free(password_hash);
        if (!std.mem.eql(u8, u.password_hash, password_hash)) {
            try self.sendBadRequest(writer, "Invalid username or password");
            return;
        }
        // Create session
        const session_id = try generateSessionId(self.allocator);
        setSession(session_id, u.id);
        // Set cookie and redirect
        const set_cookie = try std.fmt.allocPrint(self.allocator,
            "Set-Cookie: {s}={s}; HttpOnly; Path=/; Max-Age={d}",
            .{ SESSION_COOKIE_NAME, session_id, SESSION_DURATION_SECS });
        defer self.allocator.free(set_cookie);
        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 302 Found\r\n{s}\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n",
            .{ set_cookie, return_to });
        defer self.allocator.free(response);
        try writer.writeAll(response);
    }

    fn handleProtectedUrlsApi(self: *RouteHandler, writer: anytype, request: HttpRequest) !void {
        // Require authentication for all /api/urls endpoints
        const access_token = try self.requireAuthentication(request, writer);
        if (access_token == null) return; // Authentication failed, response already sent

        var token = access_token.?;
        defer token.deinit(self.allocator);

        if (std.mem.eql(u8, request.method, "GET")) {
            if (std.mem.eql(u8, request.path, "/api/urls")) {
                // List all URLs for this user
                try self.handleListUrls(writer, token.user_id);
            } else if (std.mem.startsWith(u8, request.path, "/api/urls/")) {
                // Get specific URL details
                const url_id_str = request.path[10..]; // Skip "/api/urls/"
                const url_id = std.fmt.parseInt(u64, url_id_str, 10) catch {
                    try self.sendBadRequest(writer, "Invalid URL ID");
                    return;
                };
                try self.handleGetUrl(writer, token.user_id, url_id);
            } else {
                try self.sendNotFound(writer);
            }
        } else if (std.mem.eql(u8, request.method, "POST")) {
            if (std.mem.eql(u8, request.path, "/api/urls")) {
                // Create new short URL (authenticated version)
                try self.handleCreateUrl(writer, request.body, token.user_id);
            } else {
                try self.sendNotFound(writer);
            }
        } else {
            try self.sendMethodNotAllowed(writer);
        }
    }

    fn handleListUrls(self: *RouteHandler, writer: anytype, user_id: u64) !void {
        // TODO: Implement database method to get all URLs for a user
        // For now, return a simple JSON response
    const json_response = try std.fmt.allocPrint(self.allocator, "{{\"urls\":[],\"user_id\":{d}}}", .{user_id});
        defer self.allocator.free(json_response);

    const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn handleGetUrl(self: *RouteHandler, writer: anytype, user_id: u64, url_id: u64) !void {
        _ = user_id;
        _ = url_id;
        // TODO: Implement database method to get specific URL by ID and verify ownership
        const json_response = "{\"error\":\"Not implemented yet\"}";

    const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 501 Not Implemented\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn handleCreateUrl(self: *RouteHandler, writer: anytype, body: []const u8, user_id: u64) !void {
        std.debug.print("Protected URL creation for user {d}: {s}\n", .{ user_id, body });

        // Parse JSON to get target URL
        const target_url = self.parseTargetUrl(body) orelse {
            try self.sendBadRequest(writer, "Invalid JSON or missing 'url' field");
            return;
        };
        defer self.allocator.free(target_url);

        // Generate short code with collision detection
        var short_code: shortener.ShortCode = undefined;
        var attempts: u32 = 0;
        const max_attempts = 10;

        while (attempts < max_attempts) {
            short_code = try self.url_shortener.generateRandom(6);

            // Check if this code already exists
            const exists = self.db.shortCodeExists(short_code.code) catch |err| {
                std.debug.print("Database error checking collision: {}\n", .{err});
                short_code.deinit();
                try self.sendInternalError(writer);
                return;
            };

            if (!exists) break;

            short_code.deinit();
            attempts += 1;
        }

        if (attempts >= max_attempts) {
            try self.sendInternalError(writer);
            return;
        }

        defer short_code.deinit();

        // Store in database with user ownership
        const url_id = self.db.insertUrl(short_code.code, target_url, user_id) catch |err| {
            std.debug.print("Database error inserting URL: {}\n", .{err});
            try self.sendInternalError(writer);
            return;
        };

        std.debug.print("Created authenticated short URL: {s} -> {s} (ID: {d}, User: {d})\n", .{ short_code.code, target_url, url_id, user_id });

        // Create response JSON
        const json_response = try std.fmt.allocPrint(self.allocator, "{{\"short_code\":\"{s}\",\"short_url\":\"https://{s}.{s}\",\"target_url\":\"{s}\",\"id\":{d}}}", .{ short_code.code, short_code.code, self.config.base_domain, target_url, url_id });
        defer self.allocator.free(json_response);

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn parseSubdomain(self: *RouteHandler, host: []const u8) !?[]u8 {
        // Check if host ends with our base domain
        if (!std.mem.endsWith(u8, host, self.config.base_domain)) {
            return null;
        }

        // Extract subdomain part
        const domain_start = host.len - self.config.base_domain.len;
        if (domain_start == 0) {
            return null; // No subdomain, just the base domain
        }

        // Should have a dot before the domain
        if (host[domain_start - 1] != '.') {
            return null;
        }

        const subdomain = host[0 .. domain_start - 1];
        if (subdomain.len == 0) {
            return null;
        }

        return try self.allocator.dupe(u8, subdomain);
    }

    fn handleRedirect(self: *RouteHandler, writer: anytype, short_code: []const u8) !void {
        // Look up URL from database
        var url_record = self.db.getUrlByShortCode(short_code) catch |err| {
            std.debug.print("Database error looking up {s}: {}\n", .{ short_code, err });
            try self.sendNotFound(writer);
            return;
        };

        if (url_record) |*url| {
            defer url.deinit(self.allocator);

            std.debug.print("Redirecting {s} to {s}\n", .{ short_code, url.target_url });

            // Increment hit counter
            self.db.incrementHits(short_code) catch |err| {
                std.debug.print("Failed to increment hits for {s}: {}\n", .{ short_code, err });
            };

            const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{url.target_url});
            defer self.allocator.free(response);

            try writer.writeAll(response);
        } else {
            std.debug.print("Short code {s} not found\n", .{short_code});
            try self.sendNotFound(writer);
        }
    }

    fn handleMainDomain(self: *RouteHandler, writer: anytype, path: []const u8) !void {
        if (std.mem.eql(u8, path, "/")) {
            try self.sendWelcome(writer);
        } else if (std.mem.eql(u8, path, "/health")) {
            try self.sendHealth(writer);
        } else {
            try self.sendNotFound(writer);
        }
    }

    fn handleShorten(self: *RouteHandler, writer: anytype, body: []const u8) !void {
        std.debug.print("Shorten request body: {s}\n", .{body});

        // Parse JSON to get target URL
        // For now, assume simple JSON: {"url": "https://example.com"}
        const target_url = self.parseTargetUrl(body) orelse {
            try self.sendBadRequest(writer, "Invalid JSON or missing 'url' field");
            return;
        };
        defer self.allocator.free(target_url);

        // Generate short code with collision detection
        var short_code: shortener.ShortCode = undefined;
        var attempts: u32 = 0;
        const max_attempts = 10;

        while (attempts < max_attempts) {
            short_code = try self.url_shortener.generateRandom(6);

            // Check if this code already exists
            const exists = self.db.shortCodeExists(short_code.code) catch |err| {
                std.debug.print("Database error checking collision: {}\n", .{err});
                short_code.deinit();
                try self.sendInternalError(writer);
                return;
            };

            if (!exists) break;

            short_code.deinit();
            attempts += 1;
        }

        if (attempts >= max_attempts) {
            try self.sendInternalError(writer);
            return;
        }

        defer short_code.deinit();

        // Store in database
        const url_id = self.db.insertUrl(short_code.code, target_url, null) catch |err| {
            std.debug.print("Database error inserting URL: {}\n", .{err});
            try self.sendInternalError(writer);
            return;
        };

        std.debug.print("Created short URL: {s} -> {s} (ID: {d})\n", .{ short_code.code, target_url, url_id });

        // Create response JSON
        const json_response = try std.fmt.allocPrint(self.allocator, "{{\"short_code\":\"{s}\",\"short_url\":\"https://{s}.{s}\",\"target_url\":\"{s}\"}}", .{ short_code.code, short_code.code, self.config.base_domain, target_url });
        defer self.allocator.free(json_response);

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn parseTargetUrl(self: *RouteHandler, body: []const u8) ?[]u8 {
        // Simple JSON parser for {"url": "https://example.com"}
        const url_prefix = "\"url\":\"";
        const url_start = std.mem.indexOf(u8, body, url_prefix) orelse return null;
        const value_start = url_start + url_prefix.len;

        const value_end = std.mem.indexOfPos(u8, body, value_start, "\"") orelse return null;
        const url_value = body[value_start..value_end];

        return self.allocator.dupe(u8, url_value) catch null;
    }

    fn sendWelcome(self: *RouteHandler, writer: anytype) !void {
        const html =
            \\<!DOCTYPE html>
            \\<html>
            \\<head><title>Maigo - URL Shortener</title></head>
            \\<body>
            \\<h1>Maigo - Wildcard Subdomain URL Shortener</h1>
            \\<p>Terminal-only URL shortener for geeks!</p>
            \\<p>Use the CLI or API to shorten URLs.</p>
            \\<h2>API Endpoints:</h2>
            \\<ul>
            \\<li>POST /api/shorten - Create short URL</li>
            \\<li>GET /health - Health check</li>
            \\</ul>
            \\</body>
            \\</html>
        ;

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}", .{ html.len, html });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn sendHealth(self: *RouteHandler, writer: anytype) !void {
        const json_response = "{\"status\":\"ok\",\"service\":\"maigo\"}";

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn sendNotFound(self: *RouteHandler, writer: anytype) !void {
        const error_message = "404 Not Found";

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ error_message.len, error_message });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn sendMethodNotAllowed(self: *RouteHandler, writer: anytype) !void {
        const error_message = "405 Method Not Allowed";

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ error_message.len, error_message });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    // (removed old handleOAuthAuthorize with path argument)
    fn handleOAuthAuthorize(self: *RouteHandler, writer: anytype, request: HttpRequest) !void {
        // Parse query parameters from path
        const query_start = std.mem.indexOf(u8, request.path, "?") orelse {
            try self.sendBadRequest(writer, "Missing query parameters");
            return;
        };
        const query = request.path[query_start + 1 ..];
        const client_id = self.parseQueryValue(query, "client_id") orelse {
            try self.sendBadRequest(writer, "Missing client_id parameter");
            return;
        };
        defer self.allocator.free(client_id);
        const redirect_uri = self.parseQueryValue(query, "redirect_uri") orelse {
            try self.sendBadRequest(writer, "Missing redirect_uri parameter");
            return;
        };
        defer self.allocator.free(redirect_uri);
        const response_type = self.parseQueryValue(query, "response_type") orelse {
            try self.sendBadRequest(writer, "Missing response_type parameter");
            return;
        };
        defer self.allocator.free(response_type);
        const state = self.parseQueryValue(query, "state");
        defer if (state) |s| self.allocator.free(s);

        // Check session
    const session_id = RouteHandler.getSessionIdFromRequest(request);
        const user_id = if (session_id) |sid| getSession(sid) else null;
        if (user_id == null) {
            // Not logged in, redirect to login
            const login_url = try std.fmt.allocPrint(self.allocator, "/login?return_to={s}", .{request.path});
            defer self.allocator.free(login_url);
            const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{login_url});
            defer self.allocator.free(response);
            try writer.writeAll(response);
            return;
        }

        // Validate client exists
        const client = self.db.getOAuthClient(client_id) catch |err| {
            std.debug.print("Error getting OAuth client: {}\n", .{err});
            try self.sendInternalError(writer);
            return;
        };
        if (client == null) {
            try self.sendBadRequest(writer, "Invalid client_id");
            return;
        }
        const client_data = client.?;
        defer {
            self.allocator.free(client_data.id);
            self.allocator.free(client_data.secret);
            self.allocator.free(client_data.name);
            self.allocator.free(client_data.redirect_uri);
        }
        // Validate redirect URI
        if (!std.mem.eql(u8, client_data.redirect_uri, redirect_uri)) {
            try self.sendBadRequest(writer, "Invalid redirect_uri");
            return;
        }
        // Detect OOB redirect URIs
        const oob_uris = [_][]const u8{
            "urn:ietf:wg:oauth:2.0:oob",
            "urn:ietf:wg:oauth:2.0:oob:auto",
            "oob",
        };
        var is_oob = false;
        for (oob_uris) |oob_uri| {
            if (std.mem.eql(u8, redirect_uri, oob_uri)) {
                is_oob = true;
                break;
            }
        }
        if (std.mem.eql(u8, request.method, "POST")) {
            // Parse form values
            const approve = self.parseFormValue(request.body, "approve");
            const deny = self.parseFormValue(request.body, "deny");
            if (deny != null) {
                // Denied by user
                try self.sendBadRequest(writer, "Access denied by user");
                return;
            }
            if (approve == null) {
                try self.sendBadRequest(writer, "Missing approval");
                return;
            }
            // Generate authorization code
            // TODO: Replace with real code generation logic
            const code = try self.allocator.dupe(u8, "dummy-auth-code");
            defer self.allocator.free(code);
            if (is_oob) {
                // Display code in HTML for OOB
                const html = try std.fmt.allocPrint(self.allocator,
                    "<!DOCTYPE html><html><head><title>Authorization Code</title></head><body><h1>Authorization Code</h1><p>Copy this code and paste it into your application:</p><pre style='font-size:1.5em;'>{s}</pre></body></html>",
                        .{code});
                defer self.allocator.free(html);
                const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}", .{ html.len, html });
                defer self.allocator.free(response);
                try writer.writeAll(response);
                return;
            } else {
                // Redirect with code
                var redirect_url = try std.fmt.allocPrint(self.allocator, "{s}?code={s}", .{redirect_uri, code});
                if (state) |s| {
                    redirect_url = try std.fmt.allocPrint(self.allocator, "{s}&state={s}", .{redirect_url, s});
                }
                defer self.allocator.free(redirect_url);
                const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{redirect_url});
                defer self.allocator.free(response);
                try writer.writeAll(response);
                return;
            }
        } else {
            // Show consent form (existing logic)
            const state_input = if (state) |s| try std.fmt.allocPrint(self.allocator, "<input type=\"hidden\" name=\"state\" value=\"{s}\">", .{s}) else "";
            defer if (state_input.len > 0) self.allocator.free(state_input);
            const html = try std.fmt.allocPrint(self.allocator,
                "<!DOCTYPE html><html><head><title>Authorize {s}</title></head><body><h1>Authorize {s}</h1><p>The application '{s}' wants to access your Maigo account.</p><form method='post' action='/oauth/authorize'><input type='hidden' name='client_id' value='{s}'><input type='hidden' name='redirect_uri' value='{s}'><input type='hidden' name='response_type' value='{s}'>{s}<button type='submit' name='approve' value='true'>Approve</button><button type='submit' name='deny' value='true'>Deny</button></form></body></html>",
                    .{client_data.name, client_data.name, client_data.name, client_id, redirect_uri, response_type, state_input});
            defer self.allocator.free(html);
            const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}", .{ html.len, html });
            defer self.allocator.free(response);
            try writer.writeAll(response);
        }
    }
// Password hashing (same as CLI/TUI)
fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("maigo_salt_");
    hasher.update(password);
    var hash_bytes: [32]u8 = undefined;
    hasher.final(&hash_bytes);
    var hex = try allocator.alloc(u8, 64);
    for (hash_bytes, 0..) |byte, i| {
        _ = std.fmt.formatIntBuf(hex[i*2..][0..2], byte, 16, .lower, .{});
    }
    return hex;
}

    fn handleOAuthToken(self: *RouteHandler, writer: anytype, body: []const u8) !void {
        std.debug.print("OAuth token request body: {s}\n", .{body});

        // Parse token request
        const grant_type_str = self.parseFormValue(body, "grant_type") orelse {
            try self.sendOAuthError(writer, "invalid_request", "Missing grant_type parameter");
            return;
        };
        defer self.allocator.free(grant_type_str);

        const grant_type = oauth.GrantType.fromString(grant_type_str) orelse {
            try self.sendOAuthError(writer, "unsupported_grant_type", "Unsupported grant type");
            return;
        };

        const client_id = self.parseFormValue(body, "client_id") orelse {
            try self.sendOAuthError(writer, "invalid_request", "Missing client_id parameter");
            return;
        };
        defer self.allocator.free(client_id);

        const client_secret = self.parseFormValue(body, "client_secret") orelse {
            try self.sendOAuthError(writer, "invalid_request", "Missing client_secret parameter");
            return;
        };
        defer self.allocator.free(client_secret);

        if (grant_type == .authorization_code) {
            const code = self.parseFormValue(body, "code") orelse {
                try self.sendOAuthError(writer, "invalid_request", "Missing code parameter");
                return;
            };
            defer self.allocator.free(code);

            const redirect_uri = self.parseFormValue(body, "redirect_uri") orelse {
                try self.sendOAuthError(writer, "invalid_request", "Missing redirect_uri parameter");
                return;
            };
            defer self.allocator.free(redirect_uri);

            // Create token request
            var token_request = oauth.TokenRequest{
                .grant_type = grant_type,
                .client_id = try self.allocator.dupe(u8, client_id),
                .client_secret = try self.allocator.dupe(u8, client_secret),
                .code = try self.allocator.dupe(u8, code),
                .redirect_uri = try self.allocator.dupe(u8, redirect_uri),
                .refresh_token = null,
            };
            defer token_request.deinit(self.allocator);

            // Exchange code for token
            var access_token = self.oauth_server.exchangeCodeForToken(token_request) catch |err| {
                switch (err) {
                    oauth.OAuthError.InvalidClient => {
                        try self.sendOAuthError(writer, "invalid_client", "Invalid client credentials");
                        return;
                    },
                    oauth.OAuthError.InvalidGrant => {
                        try self.sendOAuthError(writer, "invalid_grant", "Invalid or expired authorization code");
                        return;
                    },
                    oauth.OAuthError.UnsupportedGrantType => {
                        try self.sendOAuthError(writer, "unsupported_grant_type", "Unsupported grant type");
                        return;
                    },
                    else => {
                        std.debug.print("OAuth token exchange error: {}\n", .{err});
                        try self.sendInternalError(writer);
                        return;
                    },
                }
            };
            defer access_token.deinit(self.allocator);

            const expires_in = access_token.expires_at - std.time.timestamp();

            const json_response = if (access_token.refresh_token) |refresh_token|
                try std.fmt.allocPrint(self.allocator, "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":{d},\"refresh_token\":\"{s}\",\"scope\":\"{s}\"}}", .{ access_token.token, expires_in, refresh_token, access_token.scope })
            else
                try std.fmt.allocPrint(self.allocator, "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":{d},\"scope\":\"{s}\"}}", .{ access_token.token, expires_in, access_token.scope });
            defer self.allocator.free(json_response);

            const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
            defer self.allocator.free(response);

            try writer.writeAll(response);
        } else if (grant_type == .refresh_token) {
            const refresh_token = self.parseFormValue(body, "refresh_token") orelse {
                try self.sendOAuthError(writer, "invalid_request", "Missing refresh_token parameter");
                return;
            };
            defer self.allocator.free(refresh_token);

            // Create refresh token request
            var token_request = oauth.TokenRequest{
                .grant_type = grant_type,
                .client_id = try self.allocator.dupe(u8, client_id),
                .client_secret = try self.allocator.dupe(u8, client_secret),
                .code = null,
                .redirect_uri = null,
                .refresh_token = try self.allocator.dupe(u8, refresh_token),
            };
            defer token_request.deinit(self.allocator);

            // Exchange refresh token for new access token
            var access_token = self.oauth_server.exchangeCodeForToken(token_request) catch |err| {
                switch (err) {
                    oauth.OAuthError.InvalidClient => {
                        try self.sendOAuthError(writer, "invalid_client", "Invalid client credentials");
                        return;
                    },
                    oauth.OAuthError.InvalidGrant => {
                        try self.sendOAuthError(writer, "invalid_grant", "Invalid or expired refresh token");
                        return;
                    },
                    oauth.OAuthError.UnsupportedGrantType => {
                        try self.sendOAuthError(writer, "unsupported_grant_type", "Unsupported grant type");
                        return;
                    },
                    else => {
                        std.debug.print("OAuth refresh token error: {}\n", .{err});
                        try self.sendInternalError(writer);
                        return;
                    },
                }
            };
            defer access_token.deinit(self.allocator);

            const expires_in = access_token.expires_at - std.time.timestamp();

            const json_response = if (access_token.refresh_token) |new_refresh_token|
                try std.fmt.allocPrint(self.allocator, "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":{d},\"refresh_token\":\"{s}\",\"scope\":\"{s}\"}}", .{ access_token.token, expires_in, new_refresh_token, access_token.scope })
            else
                try std.fmt.allocPrint(self.allocator, "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"expires_in\":{d},\"scope\":\"{s}\"}}", .{ access_token.token, expires_in, access_token.scope });
            defer self.allocator.free(json_response);

            const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
            defer self.allocator.free(response);

            try writer.writeAll(response);
        } else {
            try self.sendOAuthError(writer, "unsupported_grant_type", "Unsupported grant type");
        }
    }

    fn parseFormValue(self: *RouteHandler, body: []const u8, key: []const u8) ?[]u8 {
        const key_prefix = std.fmt.allocPrint(self.allocator, "{s}=", .{key}) catch return null;
        defer self.allocator.free(key_prefix);

        const key_start = std.mem.indexOf(u8, body, key_prefix) orelse return null;
        const value_start = key_start + key_prefix.len;

        const value_end = std.mem.indexOfPos(u8, body, value_start, "&") orelse body.len;
        const value = body[value_start..value_end];

        return self.allocator.dupe(u8, value) catch null;
    }

    fn parseQueryValue(self: *RouteHandler, query: []const u8, key: []const u8) ?[]u8 {
        const key_prefix = std.fmt.allocPrint(self.allocator, "{s}=", .{key}) catch return null;
        defer self.allocator.free(key_prefix);

        const key_start = std.mem.indexOf(u8, query, key_prefix) orelse return null;
        const value_start = key_start + key_prefix.len;

        const value_end = std.mem.indexOfPos(u8, query, value_start, "&") orelse query.len;
        const value = query[value_start..value_end];

        return self.allocator.dupe(u8, value) catch null;
    }

    fn sendOAuthError(self: *RouteHandler, writer: anytype, error_code: []const u8, description: []const u8) !void {
        const json_response = try std.fmt.allocPrint(self.allocator, "{{\"error\":\"{s}\",\"error_description\":\"{s}\"}}", .{ error_code, description });
        defer self.allocator.free(json_response);

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}", .{ json_response.len, json_response });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn sendBadRequest(self: *RouteHandler, writer: anytype, message: []const u8) !void {
        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ message.len, message });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn sendInternalError(self: *RouteHandler, writer: anytype) !void {
        const error_message = "500 Internal Server Error";

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ error_message.len, error_message });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }

    fn authenticateRequest(self: *RouteHandler, request: HttpRequest) !?oauth.AccessToken {
        // Look for Authorization header
        const auth_header = request.authorization orelse return null;

        // Check for Bearer token
        if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
            return null;
        }

        const token = auth_header[7..]; // Skip "Bearer "

        // Validate token
        return self.oauth_server.validateToken(token) catch |err| switch (err) {
            oauth.OAuthError.TokenExpired, oauth.OAuthError.InvalidToken => null,
            else => return err,
        };
    }

    fn requireAuthentication(self: *RouteHandler, request: HttpRequest, writer: anytype) !?oauth.AccessToken {
        const access_token = try self.authenticateRequest(request);
        if (access_token == null) {
            try self.sendUnauthorized(writer);
            return null;
        }
        return access_token;
    }

    fn sendUnauthorized(self: *RouteHandler, writer: anytype) !void {
        const error_message = "401 Unauthorized";

        const response = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}", .{ error_message.len, error_message });
        defer self.allocator.free(response);

        try writer.writeAll(response);
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    handler: RouteHandler,

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) !Server {
        return Server{
            .allocator = allocator,
            .config = config,
            .handler = try RouteHandler.init(allocator, config),
        };
    }

    pub fn deinit(self: *Server) void {
        self.handler.deinit();
    }

    pub fn start(self: *Server) !void {
        const address = try net.Address.parseIp(self.config.host, self.config.port);

        var tcp_server = try address.listen(.{});
        defer tcp_server.deinit();

        std.debug.print("Maigo server listening on http://{s}:{d}\n", .{ self.config.host, self.config.port });
        std.debug.print("Base domain: {s}\n", .{self.config.base_domain});
        std.debug.print("Wildcard subdomains: *.{s}\n", .{self.config.base_domain});

        while (true) {
            const connection = try tcp_server.accept();

            // Handle each connection synchronously for now
            self.handleConnection(connection) catch |err| {
                std.debug.print("Error handling connection: {}\n", .{err});
                connection.stream.close();
                continue;
            };
        }
    }

    fn handleConnection(self: *Server, connection: net.Server.Connection) !void {
        defer connection.stream.close();

        var buffer: [4096]u8 = undefined;
        const bytes_read = try connection.stream.read(&buffer);

        if (bytes_read == 0) return;

        var request = HttpRequest.parse(self.allocator, buffer[0..bytes_read]) catch |err| {
            std.debug.print("Error parsing request: {}\n", .{err});
            return;
        };
        defer request.deinit(self.allocator);

        try self.handler.handleRequest(request, connection.stream.writer());
    }
};

test "parse subdomain" {
    const allocator = testing.allocator;
    const config = ServerConfig{ .base_domain = "maigo.dev", .db_path = ":memory:" };
    var handler = try RouteHandler.init(allocator, config);
    defer handler.deinit();

    // Test valid subdomain
    const sub1 = try handler.parseSubdomain("abc.maigo.dev");
    if (sub1) |s| {
        defer allocator.free(s);
        try testing.expectEqualStrings("abc", s);
    } else {
        try testing.expect(false);
    }

    // Test base domain (no subdomain)
    const sub2 = try handler.parseSubdomain("maigo.dev");
    try testing.expect(sub2 == null);

    // Test invalid domain
    const sub3 = try handler.parseSubdomain("example.com");
    try testing.expect(sub3 == null);

    // Test complex subdomain
    const sub4 = try handler.parseSubdomain("my-url.maigo.dev");
    if (sub4) |s| {
        defer allocator.free(s);
        try testing.expectEqualStrings("my-url", s);
    } else {
        try testing.expect(false);
    }
}
