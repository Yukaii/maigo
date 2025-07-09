const std = @import("std");
const net = std.net;
const testing = std.testing;
const shortener = @import("shortener.zig");

pub const ServerConfig = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = 8080,
    base_domain: []const u8 = "maigo.dev",
};

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    host: []const u8,
    body: []const u8,
    
    pub fn parse(allocator: std.mem.Allocator, raw_request: []const u8) !HttpRequest {
        var lines = std.mem.splitSequence(u8, raw_request, "\r\n");
        
        // Parse request line
        const request_line = lines.next() orelse return error.InvalidRequest;
        var parts = std.mem.splitSequence(u8, request_line, " ");
        const method = parts.next() orelse return error.InvalidRequest;
        const path = parts.next() orelse return error.InvalidRequest;
        
        // Parse headers
        var host: []const u8 = "";
        while (lines.next()) |line| {
            if (line.len == 0) break; // Empty line marks end of headers
            
            if (std.mem.startsWith(u8, line, "Host: ")) {
                host = line[6..];
            }
        }
        
        // Get body (remaining content)
        const body = lines.rest();
        
        return HttpRequest{
            .method = try allocator.dupe(u8, method),
            .path = try allocator.dupe(u8, path),
            .host = try allocator.dupe(u8, host),
            .body = try allocator.dupe(u8, body),
        };
    }
    
    pub fn deinit(self: *HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.method);
        allocator.free(self.path);
        allocator.free(self.host);
        allocator.free(self.body);
    }
};

pub const RouteHandler = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    url_shortener: shortener.Shortener,

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) RouteHandler {
        return RouteHandler{
            .allocator = allocator,
            .config = config,
            .url_shortener = shortener.Shortener.init(allocator),
        };
    }

    pub fn handleRequest(self: *RouteHandler, request: HttpRequest, writer: anytype) !void {
        std.debug.print("Request: {s} {s} Host: {s}\n", .{ request.method, request.path, request.host });

        // Parse subdomain from host
        const subdomain = try self.parseSubdomain(request.host);
        defer if (subdomain) |sub| self.allocator.free(sub);

        if (std.mem.eql(u8, request.method, "GET")) {
            if (subdomain) |sub| {
                // Subdomain request - redirect to full URL
                try self.handleRedirect(writer, sub);
            } else {
                // Main domain request
                try self.handleMainDomain(writer, request.path);
            }
        } else if (std.mem.eql(u8, request.method, "POST")) {
            if (std.mem.eql(u8, request.path, "/api/shorten")) {
                try self.handleShorten(writer, request.body);
            } else {
                try self.sendNotFound(writer);
            }
        } else {
            try self.sendMethodNotAllowed(writer);
        }
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
        // For now, just return a mock redirect
        // TODO: Look up actual URL from database
        const mock_url = "https://example.com";
        
        std.debug.print("Redirecting {s} to {s}\n", .{ short_code, mock_url });

        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 302 Found\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n",
            .{mock_url}
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
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

        // For now, generate a random short code
        var short_code = try self.url_shortener.generateRandom(6);
        defer short_code.deinit();

        // Create response JSON
        const json_response = try std.fmt.allocPrint(self.allocator, 
            "{{\"short_code\":\"{s}\",\"short_url\":\"https://{s}.{s}\"}}", 
            .{ short_code.code, short_code.code, self.config.base_domain }
        );
        defer self.allocator.free(json_response);

        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json_response.len, json_response }
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
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

        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ html.len, html }
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
    }

    fn sendHealth(self: *RouteHandler, writer: anytype) !void {
        const json_response = "{\"status\":\"ok\",\"service\":\"maigo\"}";
        
        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ json_response.len, json_response }
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
    }

    fn sendNotFound(self: *RouteHandler, writer: anytype) !void {
        const error_message = "404 Not Found";
        
        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ error_message.len, error_message }
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
    }

    fn sendMethodNotAllowed(self: *RouteHandler, writer: anytype) !void {
        const error_message = "405 Method Not Allowed";
        
        const response = try std.fmt.allocPrint(self.allocator,
            "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\n\r\n{s}",
            .{ error_message.len, error_message }
        );
        defer self.allocator.free(response);
        
        try writer.writeAll(response);
    }
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    config: ServerConfig,
    handler: RouteHandler,

    pub fn init(allocator: std.mem.Allocator, config: ServerConfig) Server {
        return Server{
            .allocator = allocator,
            .config = config,
            .handler = RouteHandler.init(allocator, config),
        };
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
    const config = ServerConfig{ .base_domain = "maigo.dev" };
    var handler = RouteHandler.init(allocator, config);

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