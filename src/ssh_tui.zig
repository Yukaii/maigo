const std = @import("std");
const net = std.net;
const database = @import("database.zig");

pub const SshTuiServer = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    host: []const u8,
    port: u16,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, host: []const u8, port: u16) SshTuiServer {
        return SshTuiServer{
            .allocator = allocator,
            .db = db,
            .host = host,
            .port = port,
        };
    }

    pub fn start(self: *SshTuiServer) !void {
        const address = try net.Address.parseIp(self.host, self.port);

        var tcp_server = try address.listen(.{});
        defer tcp_server.deinit();

        std.debug.print("SSH TUI server listening on {s}:{d}\n", .{ self.host, self.port });
        std.debug.print("Connect with: ssh user@{s} -p {d}\n", .{ self.host, self.port });

        while (true) {
            const connection = try tcp_server.accept();

            // Handle each connection (simplified SSH-like protocol)
            self.handleConnection(connection) catch |err| {
                std.debug.print("Error handling SSH TUI connection: {}\n", .{err});
                connection.stream.close();
                continue;
            };
        }
    }

    fn handleConnection(self: *SshTuiServer, connection: net.Server.Connection) !void {
        defer connection.stream.close();

        const writer = connection.stream.writer();
        const reader = connection.stream.reader();

        try writer.writeAll("Welcome to Maigo URL Shortener!\r\n");
        try writer.writeAll("================================\r\n\r\n");

        // Simple menu system
        while (true) {
            try writer.writeAll("Choose an option:\r\n");
            try writer.writeAll("1. Register new account\r\n");
            try writer.writeAll("2. Login to existing account\r\n");
            try writer.writeAll("3. Exit\r\n");
            try writer.writeAll("Enter choice (1-3): ");

            var input_buffer: [256]u8 = undefined;
            const input_len = try reader.read(&input_buffer);
            if (input_len == 0) break;

            const input = std.mem.trim(u8, input_buffer[0..input_len], " \r\n\t");

            if (std.mem.eql(u8, input, "1")) {
                try self.handleRegistration(writer, reader);
            } else if (std.mem.eql(u8, input, "2")) {
                try self.handleLogin(writer, reader);
            } else if (std.mem.eql(u8, input, "3")) {
                try writer.writeAll("Goodbye!\r\n");
                break;
            } else {
                try writer.writeAll("Invalid choice. Please try again.\r\n\r\n");
            }
        }
    }

    fn handleRegistration(self: *SshTuiServer, writer: anytype, reader: anytype) !void {
        try writer.writeAll("\r\n=== User Registration ===\r\n");

        // Get username
        try writer.writeAll("Enter username: ");
        var username_buffer: [256]u8 = undefined;
        const username_len = try reader.read(&username_buffer);
        if (username_len == 0) return;
        const username = std.mem.trim(u8, username_buffer[0..username_len], " \r\n\t");

        if (username.len == 0) {
            try writer.writeAll("Username cannot be empty.\r\n\r\n");
            return;
        }

        // Check if username already exists
        var existing_user = try self.db.getUserByUsername(username);
        if (existing_user) |*user| {
            user.deinit(self.allocator);
            try writer.writeAll("Username already exists. Please choose a different one.\r\n\r\n");
            return;
        }

        // Get email
        try writer.writeAll("Enter email: ");
        var email_buffer: [256]u8 = undefined;
        const email_len = try reader.read(&email_buffer);
        if (email_len == 0) return;
        const email = std.mem.trim(u8, email_buffer[0..email_len], " \r\n\t");

        if (email.len == 0 or std.mem.indexOf(u8, email, "@") == null) {
            try writer.writeAll("Invalid email address.\r\n\r\n");
            return;
        }

        // Get password
        try writer.writeAll("Enter password: ");
        var password_buffer: [256]u8 = undefined;
        const password_len = try reader.read(&password_buffer);
        if (password_len == 0) return;
        const password = std.mem.trim(u8, password_buffer[0..password_len], " \r\n\t");

        if (password.len < 6) {
            try writer.writeAll("Password must be at least 6 characters long.\r\n\r\n");
            return;
        }

        // Simple password hashing (in production, use proper bcrypt/scrypt)
        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        // Create user
        const user_id = self.db.insertUser(username, email, password_hash) catch |err| {
            if (err == database.DatabaseError.StepFailed) {
                try writer.writeAll("Registration failed. Username or email may already exist.\r\n\r\n");
                return;
            }
            return err;
        };

        try writer.writeAll("Registration successful!\r\n");
        const success_msg = try std.fmt.allocPrint(self.allocator, "User ID: {d}\r\n", .{user_id});
        defer self.allocator.free(success_msg);
        try writer.writeAll(success_msg);
        try writer.writeAll("You can now login with your credentials.\r\n\r\n");
    }

    fn handleLogin(self: *SshTuiServer, writer: anytype, reader: anytype) !void {
        try writer.writeAll("\r\n=== User Login ===\r\n");

        // Get username
        try writer.writeAll("Username: ");
        var username_buffer: [256]u8 = undefined;
        const username_len = try reader.read(&username_buffer);
        if (username_len == 0) return;
        const username = std.mem.trim(u8, username_buffer[0..username_len], " \r\n\t");

        // Get password
        try writer.writeAll("Password: ");
        var password_buffer: [256]u8 = undefined;
        const password_len = try reader.read(&password_buffer);
        if (password_len == 0) return;
        const password = std.mem.trim(u8, password_buffer[0..password_len], " \r\n\t");

        // Authenticate user
        const user_result = try self.db.getUserByUsername(username);
        if (user_result == null) {
            try writer.writeAll("Invalid username or password.\r\n\r\n");
            return;
        }

        var authenticated_user = user_result.?;
        defer authenticated_user.deinit(self.allocator);

        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        if (!std.mem.eql(u8, authenticated_user.password_hash, password_hash)) {
            try writer.writeAll("Invalid username or password.\r\n\r\n");
            return;
        }

        try writer.writeAll("Login successful!\r\n");
        const welcome_msg = try std.fmt.allocPrint(self.allocator, "Welcome back, {s}!\r\n", .{authenticated_user.username});
        defer self.allocator.free(welcome_msg);
        try writer.writeAll(welcome_msg);

        try writer.writeAll("\r\nNext steps:\r\n");
        try writer.writeAll("1. Use 'maigo auth url' to get OAuth authorization URL\r\n");
        try writer.writeAll("2. Open the URL in your browser and authorize\r\n");
        try writer.writeAll("3. Use 'maigo auth token <code>' to exchange for access token\r\n");
        try writer.writeAll("4. Start using the CLI to create short URLs!\r\n\r\n");
    }

    fn hashPassword(self: *SshTuiServer, password: []const u8) ![]u8 {
        // Simple hash (in production, use proper password hashing like bcrypt)
        // This is just for demonstration - DO NOT use in production
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("maigo_salt_"); // Add salt
        hasher.update(password);

        var hash_bytes: [32]u8 = undefined;
        hasher.final(&hash_bytes);

        // Convert to hex string
        const hex_chars = "0123456789abcdef";
        var hex_string = try self.allocator.alloc(u8, 64);
        for (hash_bytes, 0..) |byte, i| {
            hex_string[i * 2] = hex_chars[byte >> 4];
            hex_string[i * 2 + 1] = hex_chars[byte & 0xf];
        }

        return hex_string;
    }
};
