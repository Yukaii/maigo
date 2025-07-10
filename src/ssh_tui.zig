const std = @import("std");
const libssh = @import("libssh.zig");
const database_pg = @import("database_pg.zig");

pub const TUI = struct {
    allocator: std.mem.Allocator,
    db: *database_pg.Database,
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
        registration_username,
        registration_password,
        registration_confirm,
        login_username,
        login_password,
        success,
    };

    const StatusType = enum {
        info,
        success,
        err,
    };

    pub fn init(allocator: std.mem.Allocator, db: *database_pg.Database, channel: *libssh.SSHChannel) !TUI {
        std.debug.print("SSH TUI: Initializing with database pointer: {*}\n", .{db});
        return TUI{
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

    pub fn deinit(self: *TUI) void {
        self.username_buffer.deinit();
        self.email_buffer.deinit();
        self.password_buffer.deinit();
    }

    pub fn run(self: *TUI) !void {
        // Send initial setup to client - enter alternate screen and hide cursor
        try self.sendToSSH("\x1b[?1049h\x1b[H\x1b[2J\x1b[?25l");

        while (!self.should_quit) {
            // Render current screen
            try self.render();

            // Handle input from SSH channel
            try self.handleSSHInput();

            // Small delay to prevent busy waiting
            std.time.sleep(50 * std.time.ns_per_ms);
        }

        // Restore client terminal - show cursor and exit alternate screen
        try self.sendToSSH("\x1b[?25h\x1b[?1049l");
    }

    fn sendToSSH(self: *TUI, data: []const u8) !void {
        const bytes_written = libssh.ssh_channel_write(self.channel, data);
        if (bytes_written < 0) {
            return error.SSHWriteFailed;
        }
    }

    fn handleSSHInput(self: *TUI) !void {
        var buffer: [256]u8 = undefined;
        const bytes_read = libssh.ssh_channel_read_timeout(self.channel, &buffer, 0, 10); // 10ms timeout

        if (bytes_read > 0) {
            const input = buffer[0..@intCast(bytes_read)];
            try self.processInput(input);
        }
    }

    fn processInput(self: *TUI, input: []const u8) !void {
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

    fn handleEnter(self: *TUI) !void {
        switch (self.current_screen) {
            .main_menu => {},
            .registration_username => {
                if (self.username_buffer.items.len < 3) {
                    self.status_message = "Username must be at least 3 characters";
                    self.status_type = .err;
                    return;
                }
                self.current_screen = .registration_password;
                self.status_message = "Enter your password (min 6 chars)";
                self.status_type = .info;
            },
            .registration_password => {
                if (self.password_buffer.items.len < 6) {
                    self.status_message = "Password must be at least 6 characters";
                    self.status_type = .err;
                    return;
                }
                try self.processRegistration();
            },
            .registration_confirm => {
                // Not implemented, fallback to main menu
                self.current_screen = .main_menu;
            },
            .login_username => {
                if (self.username_buffer.items.len == 0) {
                    self.status_message = "Username cannot be empty";
                    self.status_type = .err;
                    return;
                }
                self.current_screen = .login_password;
                self.status_message = "Enter your password";
                self.status_type = .info;
            },
            .login_password => {
                if (self.password_buffer.items.len == 0) {
                    self.status_message = "Password cannot be empty";
                    self.status_type = .err;
                    return;
                }
                try self.processLogin();
            },
            .success => {
                self.current_screen = .main_menu;
                self.status_message = null;
            },
        }
    }

    fn handleBackspace(self: *TUI) !void {
        switch (self.current_screen) {
            .registration_username, .login_username => {
                if (self.username_buffer.items.len > 0) {
                    _ = self.username_buffer.pop();
                }
            },
            .registration_password, .login_password => {
                if (self.password_buffer.items.len > 0) {
                    _ = self.password_buffer.pop();
                }
            },
            else => {},
        }
    }

    fn handleMenuChoice(self: *TUI, choice: u8) !void {
        switch (choice) {
            '1' => {
                self.current_screen = .registration_username;
                self.clearBuffers();
                self.status_message = "Enter your username (min 3 chars)";
                self.status_type = .info;
            },
            '2' => {
                self.current_screen = .login_username;
                self.clearBuffers();
                self.status_message = "Enter your username";
                self.status_type = .info;
            },
            '3' => self.should_quit = true,
            else => {},
        }
    }

    fn handlePrintableChar(self: *TUI, char: u8) !void {
        switch (self.current_screen) {
            .registration_username, .login_username => {
                try self.username_buffer.append(char);
            },
            .registration_password, .login_password => {
                try self.password_buffer.append(char);
            },
            else => {},
        }
    }

    fn processRegistration(self: *TUI) !void {
        const username = self.username_buffer.items;
        const password = self.password_buffer.items;
        const email = "demo@example.com"; // For now, skip email input

        // Hash password
        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        // Try to register user
        std.debug.print("SSH TUI: Attempting to register user '{s}'\n", .{username});
        const user_id = self.db.insertUser(username, email, password_hash) catch |err| {
            std.debug.print("SSH TUI: Database error during registration: {}\n", .{err});
            // Handle new Postgres error set
            if (std.mem.eql(u8, @errorName(err), "QueryFailed")) {
                self.status_message = "Username already exists or query failed";
                self.status_type = .err;
                return;
            }
            if (std.mem.eql(u8, @errorName(err), "ConnectionFailed")) {
                self.status_message = "Database connection error";
                self.status_type = .err;
                return;
            }
            return err;
        };

        self.status_message = try std.fmt.allocPrint(self.allocator, "Registration successful! User ID: {d}", .{user_id});
        self.status_type = .success;
        self.current_screen = .success;
        self.clearBuffers();
    }

    fn processLogin(self: *TUI) !void {
        const username = self.username_buffer.items;
        const password = self.password_buffer.items;

        const user_result = try self.db.getUserByUsername(username);
        if (user_result == null) {
            self.status_message = "User not found";
            self.status_type = .err;
            return;
        }

        var user = user_result.?;
        defer user.deinit(self.allocator);

        // Hash entered password and compare
        const password_hash = try self.hashPassword(password);
        defer self.allocator.free(password_hash);

        if (!std.mem.eql(u8, user.password_hash, password_hash)) {
            self.status_message = "Incorrect password";
            self.status_type = .err;
            return;
        }

        self.status_message = try std.fmt.allocPrint(self.allocator, "Welcome back, {s}!", .{user.username});
        self.status_type = .success;
        self.current_screen = .success;
        self.clearBuffers();
    }

    fn clearBuffers(self: *TUI) void {
        self.username_buffer.clearRetainingCapacity();
        self.email_buffer.clearRetainingCapacity();
        self.password_buffer.clearRetainingCapacity();
        self.status_message = null;
    }

    fn render(self: *TUI) !void {
        // Clear screen and position cursor at top immediately
        try self.sendToSSH("\x1b[H\x1b[2J");

        // Build the complete screen in a buffer
        var buffer = std.ArrayList(u8).init(self.allocator);
        defer buffer.deinit();

        // Draw title bar
        const title = switch (self.current_screen) {
            .main_menu => "MAIGO URL SHORTENER - Main Menu",
            .registration_username, .registration_password, .registration_confirm => "MAIGO URL SHORTENER - Registration",
            .login_username, .login_password => "MAIGO URL SHORTENER - Login",
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
            .registration_username => try self.drawRegistrationUsername(&buffer),
            .registration_password => try self.drawRegistrationPassword(&buffer),
            .registration_confirm => try self.drawRegistrationPassword(&buffer), // fallback, not used yet
            .login_username => try self.drawLoginUsername(&buffer),
            .login_password => try self.drawLoginPassword(&buffer),
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

    fn drawMainMenu(self: *TUI, buffer: *std.ArrayList(u8)) !void {
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

    fn drawRegistrationUsername(self: *TUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Create a new account:\r\n\r\n");
        try buffer.appendSlice("  Username: ");
        if (self.username_buffer.items.len > 0) {
            try buffer.appendSlice("\x1b[32m");
            try buffer.appendSlice(self.username_buffer.items);
            try buffer.appendSlice("\x1b[0m");
        }
        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type username and press Enter\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawRegistrationPassword(self: *TUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Create a new account:\r\n\r\n");
        try buffer.appendSlice("  Password: ");
        // Show asterisks for password
        for (0..self.password_buffer.items.len) |_| try buffer.append('*');
        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type password and press Enter\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawLoginUsername(self: *TUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Sign in to your account:\r\n\r\n");
        try buffer.appendSlice("  Username: ");
        if (self.username_buffer.items.len > 0) {
            try buffer.appendSlice("\x1b[32m");
            try buffer.appendSlice(self.username_buffer.items);
            try buffer.appendSlice("\x1b[0m");
        }
        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type username and press Enter\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawLoginPassword(self: *TUI, buffer: *std.ArrayList(u8)) !void {
        try buffer.appendSlice("  Sign in to your account:\r\n\r\n");
        try buffer.appendSlice("  Password: ");
        for (0..self.password_buffer.items.len) |_| try buffer.append('*');
        try buffer.appendSlice("\r\n\r\n");
        try buffer.appendSlice("  Type password and press Enter\r\n");
        try buffer.appendSlice("  Press Ctrl+C to exit\r\n");
    }

    fn drawLogin(self: *TUI, buffer: *std.ArrayList(u8)) !void {
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

    fn drawSuccess(self: *TUI, buffer: *std.ArrayList(u8)) !void {
        _ = self;
        try buffer.appendSlice("  \x1b[32m✓ Operation completed successfully!\x1b[0m\r\n\r\n");
        try buffer.appendSlice("  Press Enter to return to main menu\r\n");
    }

    fn hashPassword(self: *TUI, password: []const u8) ![]u8 {
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
