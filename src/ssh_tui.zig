const std = @import("std");
const libssh = @import("libssh.zig");
const database = @import("database.zig");

pub const VaxisTUI = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    channel: *libssh.SSHChannel,
    should_quit: bool,
    current_screen: Screen,
    username_buffer: std.ArrayList(u8),
    email_buffer: std.ArrayList(u8),
    password_buffer: std.ArrayList(u8),
    status_message: ?[]const u8,
    status_type: StatusType,

    const Screen = enum {
        main_menu,
        registration,
        login,
        success,
    };

    const StatusType = enum {
        info,
        success,
        err,
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, channel: *libssh.SSHChannel) !VaxisTUI {
        return VaxisTUI{
            .allocator = allocator,
            .db = db,
            .channel = channel,
            .should_quit = false,
            .current_screen = .main_menu,
            .username_buffer = std.ArrayList(u8).init(allocator),
            .email_buffer = std.ArrayList(u8).init(allocator),
            .password_buffer = std.ArrayList(u8).init(allocator),
            .status_message = null,
            .status_type = .info,
        };
    }

    pub fn deinit(self: *VaxisTUI) void {
        self.username_buffer.deinit();
        self.email_buffer.deinit();
        self.password_buffer.deinit();
    }

    pub fn run(self: *VaxisTUI) !void {
        // Send initial setup to client - enter alternate screen and hide cursor
        try self.sendToSSH("\x1b[?1049h\x1b[H\x1b[2J\x1b[?25l");

        while (!self.should_quit) {
            // Handle input from SSH channel
            try self.handleSSHInput();

            // Render current screen
            try self.render();

            // Small delay to prevent busy waiting
            std.time.sleep(50 * std.time.ns_per_ms);
        }

        // Restore client terminal - show cursor and exit alternate screen
        try self.sendToSSH("\x1b[?25h\x1b[?1049l");
    }

    fn sendToSSH(self: *VaxisTUI, data: []const u8) !void {
        const bytes_written = libssh.ssh_channel_write(self.channel, data);
        if (bytes_written < 0) {
            return error.SSHWriteFailed;
        }
    }

    fn handleSSHInput(self: *VaxisTUI) !void {
        var buffer: [256]u8 = undefined;
        const bytes_read = libssh.ssh_channel_read_timeout(self.channel, &buffer, 0, 10); // 10ms timeout

        if (bytes_read > 0) {
            const input = buffer[0..@intCast(bytes_read)];
            try self.processInput(input);
        }
    }

    fn processInput(self: *VaxisTUI, input: []const u8) !void {
        for (input) |byte| {
            switch (byte) {
                '\r', '\n' => try self.handleEnter(),
                3 => self.should_quit = true, // Ctrl+C
                127, 8 => try self.handleBackspace(), // Backspace/Delete
                '1'...'9' => if (self.current_screen == .main_menu) try self.handleMenuChoice(byte) else try self.handlePrintableChar(byte),
                32...47, 58...126 => try self.handlePrintableChar(byte), // Other printable ASCII (excluding 1-9)
                else => {},
            }
        }
    }

    fn handleEnter(self: *VaxisTUI) !void {
        switch (self.current_screen) {
            .main_menu => {},
            .registration => try self.processRegistration(),
            .login => try self.processLogin(),
            .success => self.current_screen = .main_menu,
        }
    }

    fn handleBackspace(self: *VaxisTUI) !void {
        switch (self.current_screen) {
            .registration, .login => {
                // Remove last character from current input buffer
                if (self.username_buffer.items.len > 0) {
                    _ = self.username_buffer.pop();
                }
            },
            else => {},
        }
    }

    fn handleMenuChoice(self: *VaxisTUI, choice: u8) !void {
        switch (choice) {
            '1' => {
                self.current_screen = .registration;
                self.clearBuffers();
                self.status_message = "Enter your registration details";
                self.status_type = .info;
            },
            '2' => {
                self.current_screen = .login;
                self.clearBuffers();
                self.status_message = "Enter your login credentials";
                self.status_type = .info;
            },
            '3' => self.should_quit = true,
            else => {},
        }
    }

    fn handlePrintableChar(self: *VaxisTUI, char: u8) !void {
        switch (self.current_screen) {
            .registration, .login => {
                try self.username_buffer.append(char);
            },
            else => {},
        }
    }

    fn processRegistration(self: *VaxisTUI) !void {
        const username = self.username_buffer.items;
        if (username.len < 3) {
            self.status_message = "Username must be at least 3 characters";
            self.status_type = .err;
            return;
        }

        // For demo, we'll use fixed email and password
        const email = "demo@example.com";
        const password = "password123";

        // Hash password
        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        // Try to register user
        const user_id = self.db.insertUser(username, email, password_hash) catch |err| {
            if (err == database.DatabaseError.StepFailed) {
                self.status_message = "Username already exists";
                self.status_type = .err;
                return;
            }
            return err;
        };

        self.status_message = try std.fmt.allocPrint(self.allocator, "Registration successful! User ID: {d}", .{user_id});
        self.status_type = .success;
        self.current_screen = .success;
    }

    fn processLogin(self: *VaxisTUI) !void {
        const username = self.username_buffer.items;
        if (username.len == 0) {
            self.status_message = "Username cannot be empty";
            self.status_type = .err;
            return;
        }

        const user_result = try self.db.getUserByUsername(username);
        if (user_result == null) {
            self.status_message = "User not found";
            self.status_type = .err;
            return;
        }

        var user = user_result.?;
        defer user.deinit(self.allocator);

        self.status_message = try std.fmt.allocPrint(self.allocator, "Welcome back, {s}!", .{user.username});
        self.status_type = .success;
        self.current_screen = .success;
    }

    fn clearBuffers(self: *VaxisTUI) void {
        self.username_buffer.clearRetainingCapacity();
        self.email_buffer.clearRetainingCapacity();
        self.password_buffer.clearRetainingCapacity();
        self.status_message = null;
    }

    fn render(self: *VaxisTUI) !void {
        // Clear screen and position cursor at top
        try self.sendToSSH("\x1b[H\x1b[2J");

        // Build the complete screen in a buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Draw title bar
        const title = switch (self.current_screen) {
            .main_menu => "MAIGO URL SHORTENER - Main Menu",
            .registration => "MAIGO URL SHORTENER - Registration",
            .login => "MAIGO URL SHORTENER - Login",
            .success => "MAIGO URL SHORTENER - Success",
        };

        // Calculate center position for 80-column terminal
        const title_padding = (80 -| title.len) / 2;
        try buffer.appendSlice("\r\n");
        for (0..title_padding) |_| try buffer.append(' ');
        try buffer.appendSlice(title);
        try buffer.appendSlice("\r\n");

        // Draw separator
        for (0..80) |_| try buffer.append('=');
        try buffer.appendSlice("\r\n\r\n");

        // Draw screen-specific content
        switch (self.current_screen) {
            .main_menu => try self.drawMainMenu(&buffer),
            .registration => try self.drawRegistration(&buffer),
            .login => try self.drawLogin(&buffer),
            .success => try self.drawSuccess(&buffer),
        }

        // Draw status message
        if (self.status_message) |msg| {
            const status_prefix = switch (self.status_type) {
                .info => "\x1b[36mINFO:\x1b[0m ", // Cyan
                .success => "\x1b[32mSUCCESS:\x1b[0m ", // Green
                .err => "\x1b[31mERROR:\x1b[0m ", // Red
            };
            try buffer.appendSlice("\r\n\r\n  ");
            try buffer.appendSlice(status_prefix);
            try buffer.appendSlice(msg);
        }

        // Send the complete buffer to SSH client
        try self.sendToSSH(buffer.items);
    }

    fn drawMainMenu(self: *VaxisTUI, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.appendSlice("  Choose an option:\r\n");
        try buffer.appendSlice("\r\n");
        try buffer.appendSlice("    ┌─────────────────────────────────────┐\r\n");
        try buffer.appendSlice("    │ 1. Register new account             │\r\n");
        try buffer.appendSlice("    │ 2. Login to existing account        │\r\n");
        try buffer.appendSlice("    │ 3. Exit                             │\r\n");
        try buffer.appendSlice("    └─────────────────────────────────────┘\r\n");
        try buffer.appendSlice("\r\n");
        try buffer.appendSlice("  Enter your choice (1-3):\r\n");
        try buffer.appendSlice("\r\n");
    }

    fn drawRegistration(self: *VaxisTUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Create a new account:\r\n\r\n");
        try buffer.appendSlice("  Username: ");

        // Show current input
        if (self.username_buffer.items.len > 0) {
            try buffer.appendSlice("\x1b[32m"); // Green color
            try buffer.appendSlice(self.username_buffer.items);
            try buffer.appendSlice("\x1b[0m"); // Reset color
        }

        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type username and press Enter to register\r\n");
        try buffer.appendSlice("  \x1b[90m(Demo: uses fixed email/password)\x1b[0m\r\n\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawLogin(self: *VaxisTUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Sign in to your account:\r\n\r\n");
        try buffer.appendSlice("  Username: ");

        // Show current input
        if (self.username_buffer.items.len > 0) {
            try buffer.appendSlice("\x1b[32m"); // Green color
            try buffer.appendSlice(self.username_buffer.items);
            try buffer.appendSlice("\x1b[0m"); // Reset color
        }

        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type username and press Enter to login\r\n\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawSuccess(self: *VaxisTUI, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.appendSlice("  \x1b[32m✓ Operation completed successfully!\x1b[0m\r\n\r\n");
        try buffer.appendSlice("  Press Enter to return to main menu\r\n");
    }

    fn hashPassword(self: *VaxisTUI, password: []const u8) ![]u8 {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update("maigo_salt_");
        hasher.update(password);

        var hash_bytes: [32]u8 = undefined;
        hasher.final(&hash_bytes);

        const hex_chars = "0123456789abcdef";
        var hex_string = try self.allocator.alloc(u8, 64);
        for (hash_bytes, 0..) |byte, i| {
            hex_string[i * 2] = hex_chars[byte >> 4];
            hex_string[i * 2 + 1] = hex_chars[byte & 0xf];
        }

        return hex_string;
    }
};
