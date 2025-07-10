const std = @import("std");
const libssh = @import("libssh.zig");
const database = @import("database.zig");
const SSHTUI = @import("ssh_tui.zig").TUI;

pub const LibSSHServer = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    ssh_server: libssh.SSHServer,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, host: []const u8, port: u16) !LibSSHServer {
        const ssh_server = try libssh.SSHServer.init(allocator, host, port);

        return LibSSHServer{
            .allocator = allocator,
            .db = db,
            .ssh_server = ssh_server,
        };
    }

    pub fn deinit(self: *LibSSHServer) void {
        self.ssh_server.deinit();
    }

    pub fn start(self: *LibSSHServer) !void {
        std.debug.print("Maigo libssh server listening on {s}:{d}\n", .{ self.ssh_server.host, self.ssh_server.port });
        std.debug.print("Connect with: ssh user@{s} -p {d}\n", .{ self.ssh_server.host, self.ssh_server.port });
        std.debug.print("Press Ctrl+C to stop the server\n\n", .{});

        // Start listening
        try self.ssh_server.listen();

        while (true) {
            std.debug.print("Waiting for SSH connections...\n", .{});

            var connection = self.ssh_server.accept() catch |err| {
                std.debug.print("Failed to accept SSH connection: {}\n", .{err});
                continue;
            };
            defer connection.deinit();

            std.debug.print("New SSH connection established\n", .{});

            // Handle the connection
            self.handleConnection(&connection) catch |err| {
                std.debug.print("Error handling SSH connection: {}\n", .{err});
                continue;
            };

            std.debug.print("SSH connection closed\n", .{});
        }
    }

    fn handleConnection(self: *LibSSHServer, connection: *libssh.SSHConnection) !void {
        // Perform key exchange
        std.debug.print("Performing SSH key exchange\n", .{});
        try connection.handleKeyExchange();
        std.debug.print("SSH key exchange completed\n", .{});

        // Create a handler context for this connection
        var handler = ConnectionHandler{
            .allocator = self.allocator,
            .db = self.db,
            .connection = connection,
            .authenticated = false,
            .channel = null,
        };

        // Set global handler for message processing
        g_handler = &handler;
        defer {
            g_handler = null;
        }

        // Process SSH messages manually
        var authenticated = false;
        var channel: ?*libssh.SSHChannel = null;

        // Authentication loop
        while (!authenticated) {
            const msg = libssh.ssh_message_get(connection.session) orelse {
                std.debug.print("No message received, breaking\n", .{});
                break;
            };
            defer libssh.ssh_message_free(msg);

            const msg_type = libssh.ssh_message_type(msg);
            std.debug.print("Received message type: {}\n", .{msg_type});

            if (msg_type == libssh.SSH_REQUEST_AUTH) {
                const msg_subtype = libssh.ssh_message_subtype(msg);
                std.debug.print("Auth method: {}\n", .{msg_subtype});

                if (msg_subtype == libssh.SSH_AUTH_METHOD_NONE) {
                    // Client is asking what auth methods are available - accept immediately
                    std.debug.print("Client requesting available auth methods - accepting none auth\n", .{});
                    if (libssh.ssh_message_auth_reply_success(msg, 0) == libssh.SSH_OK) {
                        std.debug.print("Authentication successful with none method\n", .{});
                        authenticated = true;
                        continue;
                    }
                } else if (msg_subtype == libssh.SSH_AUTH_METHOD_PASSWORD) {
                    const user = libssh.ssh_message_auth_user(msg);
                    const password = libssh.ssh_message_auth_password(msg);

                    std.debug.print("Authentication attempt: user={s}, password={s}\n", .{ user, password });

                    // For demo purposes, accept any user/password
                    if (libssh.ssh_message_auth_reply_success(msg, 0) == libssh.SSH_OK) {
                        std.debug.print("Authentication successful\n", .{});
                        authenticated = true;
                        continue;
                    } else {
                        std.debug.print("Failed to send auth success reply\n", .{});
                    }
                } else {
                    std.debug.print("Unsupported auth method: {}\n", .{msg_subtype});
                    _ = libssh.ssh_message_auth_reply_default(msg);
                }
            } else if (msg_type == libssh.SSH_REQUEST_SERVICE) {
                std.debug.print("Service request received\n", .{});
                _ = libssh.ssh_message_reply_default(msg);
            } else {
                std.debug.print("Unhandled message type during auth: {}\n", .{msg_type});
                _ = libssh.ssh_message_reply_default(msg);
            }
        }

        if (!authenticated) {
            std.debug.print("Authentication failed\n", .{});
            return;
        }

        // Channel setup loop
        while (channel == null) {
            const msg = libssh.ssh_message_get(connection.session) orelse {
                std.debug.print("No channel message received\n", .{});
                break;
            };
            defer libssh.ssh_message_free(msg);

            const msg_type = libssh.ssh_message_type(msg);
            std.debug.print("Received channel message type: {}\n", .{msg_type});

            if (msg_type == libssh.SSH_REQUEST_CHANNEL_OPEN) {
                const msg_subtype = libssh.ssh_message_subtype(msg);
                if (msg_subtype == libssh.SSH_CHANNEL_SESSION) {
                    std.debug.print("Channel open request received\n", .{});
                    channel = libssh.ssh_message_channel_request_open_reply_accept(msg);
                    if (channel) |_| {
                        std.debug.print("Channel opened successfully\n", .{});
                    }
                }
            }
        }

        if (channel) |ch| {
            // Handle channel requests (pty, shell, etc.)
            var pty_allocated = false;
            var shell_requested = false;

            while (!shell_requested) {
                const msg = libssh.ssh_message_get(connection.session) orelse {
                    std.debug.print("No shell message received\n", .{});
                    break;
                };
                defer libssh.ssh_message_free(msg);

                const msg_type = libssh.ssh_message_type(msg);
                if (msg_type == libssh.SSH_REQUEST_CHANNEL) {
                    const msg_subtype = libssh.ssh_message_subtype(msg);

                    if (msg_subtype == libssh.SSH_CHANNEL_REQUEST_PTY) {
                        std.debug.print("PTY request received\n", .{});

                        // Get terminal size from PTY request
                        const term_type = libssh.ssh_message_channel_request_pty_term(msg);
                        const cols = libssh.ssh_message_channel_request_pty_width(msg);
                        const rows = libssh.ssh_message_channel_request_pty_height(msg);

                        std.debug.print("PTY details - term: {s}, cols: {d}, rows: {d}\n", .{ term_type, cols, rows });

                        if (libssh.ssh_message_channel_request_reply_success(msg) == libssh.SSH_OK) {
                            std.debug.print("PTY request accepted\n", .{});
                            pty_allocated = true;
                        }
                    } else if (msg_subtype == libssh.SSH_CHANNEL_REQUEST_SHELL) {
                        std.debug.print("Shell request received\n", .{});

                        if (libssh.ssh_message_channel_request_reply_success(msg) == libssh.SSH_OK) {
                            std.debug.print("Shell request accepted\n", .{});
                            shell_requested = true;
                        }
                    } else {
                        std.debug.print("Other channel request: {}\n", .{msg_subtype});
                        _ = libssh.ssh_message_channel_request_reply_success(msg);
                    }
                }
            }

            if (shell_requested) {
                // Start enhanced SSH TUI session
                try startEnhancedTuiSession(&handler, ch);
            }
        }
    }
};

const ConnectionHandler = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    connection: *libssh.SSHConnection,
    authenticated: bool,
    channel: ?*libssh.SSHChannel,
};

// Global handler for processing messages (workaround for callback limitations)
var g_handler: ?*ConnectionHandler = null;

fn connectionMessageHandler(msg: *libssh.SSHMessage) void {
    if (g_handler) |handler| {
        processMessage(handler, msg);
    }
}

fn processMessage(handler: *ConnectionHandler, msg: *libssh.SSHMessage) void {
    const msg_type = libssh.ssh_message_type(msg);

    if (msg_type == libssh.SSH_REQUEST_AUTH) {
        handleAuthenticationMessage(handler, msg);
    } else if (msg_type == libssh.SSH_REQUEST_CHANNEL_OPEN) {
        handleChannelOpenMessage(handler, msg);
    } else if (msg_type == libssh.SSH_REQUEST_CHANNEL) {
        handleChannelRequestMessage(handler, msg);
    } else {
        std.debug.print("Unhandled SSH message type: {}\n", .{msg_type});
    }
}

fn handleAuthenticationMessage(handler: *ConnectionHandler, msg: *libssh.SSHMessage) void {
    const msg_subtype = libssh.ssh_message_subtype(msg);

    if (msg_subtype == libssh.SSH_AUTH_METHOD_PASSWORD) {
        const user = libssh.ssh_message_auth_user(msg);
        const password = libssh.ssh_message_auth_password(msg);

        std.debug.print("Authentication attempt: user={s}\n", .{user});

        // For demo purposes, authenticate any user with any password
        // In production, implement proper authentication against the database
        if (authenticateUser(handler, user, password)) {
            if (libssh.ssh_message_auth_reply_success(msg, 0) == libssh.SSH_OK) {
                std.debug.print("Authentication successful for user: {s}\n", .{user});
                handler.authenticated = true;
                return;
            }
        }

        std.debug.print("Authentication failed for user: {s}\n", .{user});
    }

    // Reject authentication
    _ = libssh.ssh_message_auth_reply_default(msg);
}

fn handleChannelOpenMessage(handler: *ConnectionHandler, msg: *libssh.SSHMessage) void {
    const msg_subtype = libssh.ssh_message_subtype(msg);

    if (msg_subtype == libssh.SSH_CHANNEL_SESSION) {
        std.debug.print("Channel open request received\n", .{});

        const channel = libssh.ssh_message_channel_request_open_reply_accept(msg);
        if (channel) |ch| {
            handler.channel = ch;
            std.debug.print("Channel opened successfully\n", .{});
        } else {
            std.debug.print("Failed to open channel\n", .{});
        }
    }
}

fn handleChannelRequestMessage(handler: *ConnectionHandler, msg: *libssh.SSHMessage) void {
    const msg_subtype = libssh.ssh_message_subtype(msg);

    if (msg_subtype == libssh.SSH_CHANNEL_REQUEST_SHELL or
        msg_subtype == libssh.SSH_CHANNEL_REQUEST_PTY)
    {
        std.debug.print("Channel request: shell/pty\n", .{});

        if (libssh.ssh_message_channel_request_reply_success(msg) == libssh.SSH_OK) {
            std.debug.print("Channel request accepted\n", .{});

            // Start the TUI session
            if (handler.channel) |channel| {
                startTuiSession(handler, channel) catch |err| {
                    std.debug.print("TUI session error: {}\n", .{err});
                };
            }
        }
    }
}

fn authenticateUser(handler: *ConnectionHandler, user: [*:0]const u8, password: [*:0]const u8) bool {
    _ = handler;
    _ = user;
    _ = password;

    // For demo purposes, accept any authentication
    // In production, verify against the database
    return true;
}

fn startEnhancedTuiSession(handler: *ConnectionHandler, channel: *libssh.SSHChannel) !void {
    std.debug.print("Starting enhanced SSH TUI session\n", .{});

    // Initialize the enhanced TUI
    var tui = SSHTUI.init(handler.allocator, handler.db, channel) catch |err| {
        std.debug.print("Failed to initialize SSH TUI: {}\n", .{err});
        return err;
    };
    defer tui.deinit();

    // Run the enhanced TUI
    tui.run() catch |err| {
        std.debug.print("SSH TUI error: {}\n", .{err});
        return err;
    };
}

fn startTuiSession(handler: *ConnectionHandler, channel: *libssh.SSHChannel) !void {
    std.debug.print("Starting TUI session\n", .{});

    // Initialize terminal with proper escape sequences
    const terminal_init = "\x1b[2J\x1b[H\x1b[?25h"; // Clear screen, move cursor to home, show cursor

    const bytes_written = libssh.ssh_channel_write(channel, terminal_init);
    if (bytes_written < 0) {
        std.debug.print("Failed to write terminal init, bytes: {}\n", .{bytes_written});
        return error.ChannelWriteFailed;
    }
    std.debug.print("Terminal init written, {} bytes\n", .{bytes_written});

    // Send welcome message
    const welcome_msg =
        \\Welcome to Maigo URL Shortener!
        \\================================
        \\
        \\╔════════════════════════════════════════╗
        \\║        Maigo URL Shortener             ║
        \\║        SSH Terminal Interface          ║
        \\╚════════════════════════════════════════╝
        \\
        \\
    ;

    const welcome_bytes = libssh.ssh_channel_write(channel, welcome_msg);
    if (welcome_bytes < 0) {
        std.debug.print("Failed to write welcome message, bytes: {}\n", .{welcome_bytes});
        return error.ChannelWriteFailed;
    }
    std.debug.print("Welcome message written, {} bytes\n", .{welcome_bytes});

    // Main TUI loop
    while (libssh.ssh_channel_is_open(channel) != 0) {
        // Send menu
        const menu_msg =
            \\┌─ Main Menu ─────────────────────────┐
            \\│ 1. Register new account             │
            \\│ 2. Login to existing account        │
            \\│ 3. Exit                             │
            \\└─────────────────────────────────────┘
            \\
            \\Enter choice (1-3):
        ;

        const menu_bytes_written = libssh.ssh_channel_write(channel, menu_msg);
        if (menu_bytes_written < 0) {
            std.debug.print("Failed to write menu, bytes: {}\n", .{menu_bytes_written});
            break;
        }
        std.debug.print("Menu written, {} bytes\n", .{menu_bytes_written});

        // Read user input
        var buffer: [256]u8 = undefined;
        const bytes_read = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000); // 30 second timeout

        if (bytes_read <= 0) {
            if (libssh.ssh_channel_is_eof(channel) != 0) {
                std.debug.print("Channel EOF reached\n", .{});
                break;
            }
            continue;
        }

        const input = std.mem.trim(u8, buffer[0..@intCast(bytes_read)], " \r\n\t");
        std.debug.print("Received input: '{s}'\n", .{input});

        if (std.mem.eql(u8, input, "1")) {
            try handleRegistration(handler, channel);
        } else if (std.mem.eql(u8, input, "2")) {
            try handleLogin(handler, channel);
        } else if (std.mem.eql(u8, input, "3")) {
            const goodbye_msg =
                \\
                \\Thank you for using Maigo!
                \\Goodbye! 👋
                \\
            ;
            _ = libssh.ssh_channel_write(channel, goodbye_msg);
            break;
        } else {
            const error_msg =
                \\
                \\❌ Invalid choice. Please enter 1, 2, or 3.
                \\
                \\
            ;
            _ = libssh.ssh_channel_write(channel, error_msg);
        }
    }

    std.debug.print("TUI session ended\n", .{});
}

fn handleRegistration(handler: *ConnectionHandler, channel: *libssh.SSHChannel) !void {
    const reg_header =
        \\
        \\┌─ User Registration ─────────────────┐
        \\│ Create a new Maigo account         │
        \\└─────────────────────────────────────┘
        \\
        \\👤 Enter username:
    ;

    if (libssh.ssh_channel_write(channel, reg_header) < 0) {
        return error.ChannelWriteFailed;
    }

    // Read username
    var buffer: [256]u8 = undefined;
    const bytes_read = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);

    if (bytes_read <= 0) {
        return error.ReadTimeout;
    }

    const username = std.mem.trim(u8, buffer[0..@intCast(bytes_read)], " \r\n\t");

    if (username.len < 3) {
        const error_msg =
            \\❌ Username must be at least 3 characters long.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Check if username exists
    var existing_user = try handler.db.getUserByUsername(username);
    if (existing_user) |*user| {
        user.deinit(handler.allocator);
        const error_msg =
            \\❌ Username already exists. Please choose a different one.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Get email
    const email_prompt =
        \\📧 Enter email:
    ;

    if (libssh.ssh_channel_write(channel, email_prompt) < 0) {
        return error.ChannelWriteFailed;
    }

    const email_bytes = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);
    if (email_bytes <= 0) {
        return error.ReadTimeout;
    }

    const email = std.mem.trim(u8, buffer[0..@intCast(email_bytes)], " \r\n\t");

    if (email.len == 0 or std.mem.indexOf(u8, email, "@") == null) {
        const error_msg =
            \\❌ Invalid email address.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Get password
    const password_prompt =
        \\🔒 Enter password (min 6 chars):
    ;

    if (libssh.ssh_channel_write(channel, password_prompt) < 0) {
        return error.ChannelWriteFailed;
    }

    const password_bytes = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);
    if (password_bytes <= 0) {
        return error.ReadTimeout;
    }

    const password = std.mem.trim(u8, buffer[0..@intCast(password_bytes)], " \r\n\t");

    if (password.len < 6) {
        const error_msg =
            \\❌ Password must be at least 6 characters long.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Create user
    const creating_msg =
        \\🔄 Creating account...
        \\
    ;
    _ = libssh.ssh_channel_write(channel, creating_msg);

    // Hash password
    const password_hash = try hashPassword(handler.allocator, password);
    defer handler.allocator.free(password_hash);

    // Insert user
    const user_id = handler.db.insertUser(username, email, password_hash) catch |err| {
        if (err == database.DatabaseError.StepFailed) {
            const error_msg =
                \\❌ Registration failed. Username or email may already exist.
                \\
                \\
            ;
            _ = libssh.ssh_channel_write(channel, error_msg);
            return;
        }
        return err;
    };

    // Success message
    const success_msg = try std.fmt.allocPrint(handler.allocator,
        \\✅ Registration successful!
        \\   User ID: {d}
        \\   You can now login with your credentials.
        \\
        \\Press Enter to continue...
    , .{user_id});
    defer handler.allocator.free(success_msg);

    _ = libssh.ssh_channel_write(channel, success_msg);

    // Wait for Enter
    _ = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);
}

fn handleLogin(handler: *ConnectionHandler, channel: *libssh.SSHChannel) !void {
    const login_header =
        \\
        \\┌─ User Login ────────────────────────┐
        \\│ Sign in to your Maigo account      │
        \\└─────────────────────────────────────┘
        \\
        \\👤 Username:
    ;

    if (libssh.ssh_channel_write(channel, login_header) < 0) {
        return error.ChannelWriteFailed;
    }

    // Read username
    var buffer: [256]u8 = undefined;
    const bytes_read = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);

    if (bytes_read <= 0) {
        return error.ReadTimeout;
    }

    const username = std.mem.trim(u8, buffer[0..@intCast(bytes_read)], " \r\n\t");

    if (username.len == 0) {
        const error_msg =
            \\❌ Username cannot be empty.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Get password
    const password_prompt =
        \\🔒 Password:
    ;

    if (libssh.ssh_channel_write(channel, password_prompt) < 0) {
        return error.ChannelWriteFailed;
    }

    const password_bytes = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);
    if (password_bytes <= 0) {
        return error.ReadTimeout;
    }

    const password = std.mem.trim(u8, buffer[0..@intCast(password_bytes)], " \r\n\t");

    if (password.len == 0) {
        const error_msg =
            \\❌ Password cannot be empty.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Authenticate
    const auth_msg =
        \\🔄 Authenticating...
        \\
    ;
    _ = libssh.ssh_channel_write(channel, auth_msg);

    // Verify credentials
    const user_result = try handler.db.getUserByUsername(username);
    if (user_result == null) {
        const error_msg =
            \\❌ Invalid username or password.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    var authenticated_user = user_result.?;
    defer authenticated_user.deinit(handler.allocator);

    const password_hash = try hashPassword(handler.allocator, password);
    defer handler.allocator.free(password_hash);

    if (!std.mem.eql(u8, authenticated_user.password_hash, password_hash)) {
        const error_msg =
            \\❌ Invalid username or password.
            \\
            \\
        ;
        _ = libssh.ssh_channel_write(channel, error_msg);
        return;
    }

    // Success
    const success_msg = try std.fmt.allocPrint(handler.allocator,
        \\✅ Login successful!
        \\   Welcome back, {s}!
        \\
        \\📋 Next steps for CLI usage:
        \\   1. Run: maigo login
        \\   2. Run: maigo auth url
        \\   3. Open URL in browser and authorize
        \\   4. Run: maigo auth token <code>
        \\   5. Start creating short URLs!
        \\
        \\Press Enter to continue...
    , .{authenticated_user.username});
    defer handler.allocator.free(success_msg);

    _ = libssh.ssh_channel_write(channel, success_msg);

    // Wait for Enter
    _ = libssh.ssh_channel_read_timeout(channel, &buffer, 0, 30000);
}

fn hashPassword(allocator: std.mem.Allocator, password: []const u8) ![]u8 {
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
