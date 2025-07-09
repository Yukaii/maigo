const std = @import("std");

// libssh C bindings
pub const c = @cImport({
    @cInclude("libssh/libssh.h");
    @cInclude("libssh/server.h");
    @cInclude("libssh/callbacks.h");
});

// SSH error codes
pub const SSH_OK = c.SSH_OK;
pub const SSH_ERROR = c.SSH_ERROR;
pub const SSH_AGAIN = c.SSH_AGAIN;
pub const SSH_EOF = c.SSH_EOF;

// SSH session states
pub const SSH_SESSION_STATE_NONE = c.SSH_SESSION_STATE_NONE;
pub const SSH_SESSION_STATE_CONNECTING = c.SSH_SESSION_STATE_CONNECTING;
pub const SSH_SESSION_STATE_SOCKET_CONNECTED = c.SSH_SESSION_STATE_SOCKET_CONNECTED;
pub const SSH_SESSION_STATE_BANNER_RECEIVED = c.SSH_SESSION_STATE_BANNER_RECEIVED;
pub const SSH_SESSION_STATE_BANNER_SENT = c.SSH_SESSION_STATE_BANNER_SENT;
pub const SSH_SESSION_STATE_INITIAL_KEX = c.SSH_SESSION_STATE_INITIAL_KEX;
pub const SSH_SESSION_STATE_KEXINIT_RECEIVED = c.SSH_SESSION_STATE_KEXINIT_RECEIVED;
pub const SSH_SESSION_STATE_DH = c.SSH_SESSION_STATE_DH;
pub const SSH_SESSION_STATE_AUTHENTICATING = c.SSH_SESSION_STATE_AUTHENTICATING;
pub const SSH_SESSION_STATE_AUTHENTICATED = c.SSH_SESSION_STATE_AUTHENTICATED;
pub const SSH_SESSION_STATE_ERROR = c.SSH_SESSION_STATE_ERROR;
pub const SSH_SESSION_STATE_DISCONNECTED = c.SSH_SESSION_STATE_DISCONNECTED;

// SSH authentication methods
pub const SSH_AUTH_METHOD_NONE = c.SSH_AUTH_METHOD_NONE;
pub const SSH_AUTH_METHOD_PASSWORD = c.SSH_AUTH_METHOD_PASSWORD;
pub const SSH_AUTH_METHOD_PUBLICKEY = c.SSH_AUTH_METHOD_PUBLICKEY;
pub const SSH_AUTH_METHOD_HOSTBASED = c.SSH_AUTH_METHOD_HOSTBASED;
pub const SSH_AUTH_METHOD_INTERACTIVE = c.SSH_AUTH_METHOD_INTERACTIVE;
pub const SSH_AUTH_METHOD_GSSAPI_MIC = c.SSH_AUTH_METHOD_GSSAPI_MIC;

// SSH authentication results
pub const SSH_AUTH_ERROR = c.SSH_AUTH_ERROR;
pub const SSH_AUTH_DENIED = c.SSH_AUTH_DENIED;
pub const SSH_AUTH_PARTIAL = c.SSH_AUTH_PARTIAL;
pub const SSH_AUTH_SUCCESS = c.SSH_AUTH_SUCCESS;
pub const SSH_AUTH_AGAIN = c.SSH_AUTH_AGAIN;

// SSH channel types
pub const SSH_CHANNEL_SESSION = c.SSH_CHANNEL_SESSION;
pub const SSH_CHANNEL_DIRECT_TCPIP = c.SSH_CHANNEL_DIRECT_TCPIP;
pub const SSH_CHANNEL_FORWARDED_TCPIP = c.SSH_CHANNEL_FORWARDED_TCPIP;
pub const SSH_CHANNEL_X11 = c.SSH_CHANNEL_X11;
pub const SSH_CHANNEL_UNKNOWN = c.SSH_CHANNEL_UNKNOWN;

// SSH channel states
pub const SSH_CHANNEL_STATE_NOT_OPEN = c.SSH_CHANNEL_STATE_NOT_OPEN;
pub const SSH_CHANNEL_STATE_OPENING = c.SSH_CHANNEL_STATE_OPENING;
pub const SSH_CHANNEL_STATE_OPEN_DENIED = c.SSH_CHANNEL_STATE_OPEN_DENIED;
pub const SSH_CHANNEL_STATE_OPEN = c.SSH_CHANNEL_STATE_OPEN;
pub const SSH_CHANNEL_STATE_CLOSED = c.SSH_CHANNEL_STATE_CLOSED;

// SSH message types
pub const SSH_REQUEST_AUTH = c.SSH_REQUEST_AUTH;
pub const SSH_REQUEST_CHANNEL_OPEN = c.SSH_REQUEST_CHANNEL_OPEN;
pub const SSH_REQUEST_CHANNEL = c.SSH_REQUEST_CHANNEL;
pub const SSH_REQUEST_SERVICE = c.SSH_REQUEST_SERVICE;
pub const SSH_REQUEST_GLOBAL = c.SSH_REQUEST_GLOBAL;

// SSH message subtypes
pub const SSH_CHANNEL_REQUEST_PTY = c.SSH_CHANNEL_REQUEST_PTY;
pub const SSH_CHANNEL_REQUEST_EXEC = c.SSH_CHANNEL_REQUEST_EXEC;
pub const SSH_CHANNEL_REQUEST_SHELL = c.SSH_CHANNEL_REQUEST_SHELL;
pub const SSH_CHANNEL_REQUEST_ENV = c.SSH_CHANNEL_REQUEST_ENV;
pub const SSH_CHANNEL_REQUEST_SUBSYSTEM = c.SSH_CHANNEL_REQUEST_SUBSYSTEM;
pub const SSH_CHANNEL_REQUEST_WINDOW_CHANGE = c.SSH_CHANNEL_REQUEST_WINDOW_CHANGE;

// SSH log levels
pub const SSH_LOG_NOLOG = c.SSH_LOG_NOLOG;
pub const SSH_LOG_WARNING = c.SSH_LOG_WARNING;
pub const SSH_LOG_PROTOCOL = c.SSH_LOG_PROTOCOL;
pub const SSH_LOG_PACKET = c.SSH_LOG_PACKET;
pub const SSH_LOG_FUNCTIONS = c.SSH_LOG_FUNCTIONS;

// SSH bind options
pub const SSH_BIND_OPTIONS_BINDADDR = c.SSH_BIND_OPTIONS_BINDADDR;
pub const SSH_BIND_OPTIONS_BINDPORT = c.SSH_BIND_OPTIONS_BINDPORT;
pub const SSH_BIND_OPTIONS_BINDPORT_STR = c.SSH_BIND_OPTIONS_BINDPORT_STR;
pub const SSH_BIND_OPTIONS_HOSTKEY = c.SSH_BIND_OPTIONS_HOSTKEY;
pub const SSH_BIND_OPTIONS_DSAKEY = c.SSH_BIND_OPTIONS_DSAKEY;
pub const SSH_BIND_OPTIONS_RSAKEY = c.SSH_BIND_OPTIONS_RSAKEY;
pub const SSH_BIND_OPTIONS_BANNER = c.SSH_BIND_OPTIONS_BANNER;
pub const SSH_BIND_OPTIONS_LOG_VERBOSITY = c.SSH_BIND_OPTIONS_LOG_VERBOSITY;
pub const SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = c.SSH_BIND_OPTIONS_LOG_VERBOSITY_STR;
pub const SSH_BIND_OPTIONS_ECDSAKEY = c.SSH_BIND_OPTIONS_ECDSAKEY;
pub const SSH_BIND_OPTIONS_PROCESS_CONFIG = c.SSH_BIND_OPTIONS_PROCESS_CONFIG;

// Wrapper types for better Zig integration
pub const SSHSession = opaque {};
pub const SSHBind = opaque {};
pub const SSHChannel = opaque {};
pub const SSHMessage = opaque {};
pub const SSHEvent = opaque {};
pub const SSHKey = opaque {};

// Function wrappers for libssh
pub fn ssh_init() c_int {
    return c.ssh_init();
}

pub fn ssh_finalize() c_int {
    return c.ssh_finalize();
}

pub fn ssh_new() ?*SSHSession {
    return @ptrCast(c.ssh_new());
}

pub fn ssh_free(session: *SSHSession) void {
    c.ssh_free(@ptrCast(session));
}

pub fn ssh_bind_new() ?*SSHBind {
    return @ptrCast(c.ssh_bind_new());
}

pub fn ssh_bind_free(bind: *SSHBind) void {
    c.ssh_bind_free(@ptrCast(bind));
}

pub fn ssh_bind_options_set(bind: *SSHBind, option: c_uint, value: ?*const anyopaque) c_int {
    return c.ssh_bind_options_set(@ptrCast(bind), option, value);
}

pub fn ssh_bind_listen(bind: *SSHBind) c_int {
    return c.ssh_bind_listen(@ptrCast(bind));
}

pub fn ssh_bind_accept(bind: *SSHBind, session: *SSHSession) c_int {
    return c.ssh_bind_accept(@ptrCast(bind), @ptrCast(session));
}

pub fn ssh_handle_key_exchange(session: *SSHSession) c_int {
    return c.ssh_handle_key_exchange(@ptrCast(session));
}

pub fn ssh_message_get(session: *SSHSession) ?*SSHMessage {
    return @ptrCast(c.ssh_message_get(@ptrCast(session)));
}

pub fn ssh_message_type(msg: *SSHMessage) c_int {
    return c.ssh_message_type(@ptrCast(msg));
}

pub fn ssh_message_subtype(msg: *SSHMessage) c_int {
    return c.ssh_message_subtype(@ptrCast(msg));
}

pub fn ssh_message_free(msg: *SSHMessage) void {
    c.ssh_message_free(@ptrCast(msg));
}

pub fn ssh_message_auth_user(msg: *SSHMessage) [*:0]const u8 {
    return c.ssh_message_auth_user(@ptrCast(msg));
}

pub fn ssh_message_auth_password(msg: *SSHMessage) [*:0]const u8 {
    return c.ssh_message_auth_password(@ptrCast(msg));
}

pub fn ssh_message_auth_reply_success(msg: *SSHMessage, partial: c_int) c_int {
    return c.ssh_message_auth_reply_success(@ptrCast(msg), partial);
}

pub fn ssh_message_auth_reply_default(msg: *SSHMessage) c_int {
    return c.ssh_message_reply_default(@ptrCast(msg));
}

pub fn ssh_message_reply_default(msg: *SSHMessage) c_int {
    return c.ssh_message_reply_default(@ptrCast(msg));
}

pub fn ssh_message_channel_request_open_reply_accept(msg: *SSHMessage) ?*SSHChannel {
    return @ptrCast(c.ssh_message_channel_request_open_reply_accept(@ptrCast(msg)));
}

pub fn ssh_message_channel_request_reply_success(msg: *SSHMessage) c_int {
    return c.ssh_message_channel_request_reply_success(@ptrCast(msg));
}

pub fn ssh_channel_write(channel: *SSHChannel, data: []const u8) c_int {
    return c.ssh_channel_write(@ptrCast(channel), data.ptr, @intCast(data.len));
}

pub fn ssh_channel_read(channel: *SSHChannel, buffer: []u8, is_stderr: c_int) c_int {
    return c.ssh_channel_read(@ptrCast(channel), buffer.ptr, @intCast(buffer.len), is_stderr);
}

pub fn ssh_channel_read_timeout(channel: *SSHChannel, buffer: []u8, is_stderr: c_int, timeout_ms: c_int) c_int {
    return c.ssh_channel_read_timeout(@ptrCast(channel), buffer.ptr, @intCast(buffer.len), is_stderr, timeout_ms);
}

pub fn ssh_channel_is_open(channel: *SSHChannel) c_int {
    return c.ssh_channel_is_open(@ptrCast(channel));
}

pub fn ssh_channel_is_eof(channel: *SSHChannel) c_int {
    return c.ssh_channel_is_eof(@ptrCast(channel));
}

pub fn ssh_channel_close(channel: *SSHChannel) c_int {
    return c.ssh_channel_close(@ptrCast(channel));
}

pub fn ssh_channel_free(channel: *SSHChannel) void {
    c.ssh_channel_free(@ptrCast(channel));
}

pub fn ssh_get_error(session: *SSHSession) [*:0]const u8 {
    return c.ssh_get_error(@ptrCast(session));
}

pub fn ssh_get_error_bind(bind: *SSHBind) [*:0]const u8 {
    return c.ssh_get_error(@ptrCast(bind));
}

pub fn ssh_get_error_code(session: *SSHSession) c_int {
    return c.ssh_get_error_code(@ptrCast(session));
}

pub fn ssh_set_log_level(level: c_int) c_int {
    return c.ssh_set_log_level(level);
}

pub fn ssh_message_channel_request_pty_term(msg: *SSHMessage) [*:0]const u8 {
    return c.ssh_message_channel_request_pty_term(@ptrCast(msg));
}

pub fn ssh_message_channel_request_pty_width(msg: *SSHMessage) c_int {
    return c.ssh_message_channel_request_pty_width(@ptrCast(msg));
}

pub fn ssh_message_channel_request_pty_height(msg: *SSHMessage) c_int {
    return c.ssh_message_channel_request_pty_height(@ptrCast(msg));
}

// Higher-level Zig wrappers for easier use
pub const SSHServer = struct {
    allocator: std.mem.Allocator,
    bind: *SSHBind,
    host: []const u8,
    port: u16,
    
    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !SSHServer {
        // Initialize libssh
        if (ssh_init() != SSH_OK) {
            return error.SSHInitFailed;
        }
        
        // Set log level
        _ = ssh_set_log_level(SSH_LOG_PROTOCOL);
        
        // Create SSH bind
        const bind = ssh_bind_new() orelse {
            return error.SSHBindCreateFailed;
        };
        
        // Set bind options
        const port_str = try std.fmt.allocPrintZ(allocator, "{d}", .{port});
        defer allocator.free(port_str);
        
        const host_cstr = try allocator.dupeZ(u8, host);
        defer allocator.free(host_cstr);
        
        if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, host_cstr.ptr) != SSH_OK) {
            ssh_bind_free(bind);
            return error.SSHBindSetAddressFailed;
        }
        
        if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, port_str.ptr) != SSH_OK) {
            ssh_bind_free(bind);
            return error.SSHBindSetPortFailed;
        }
        
        // Set up SSH host keys
        std.debug.print("Setting up SSH server with host keys\n", .{});
        
        // Try to set RSA key
        const rsa_key_path = "tmp_keys/ssh_host_rsa_key";
        if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, rsa_key_path) != SSH_OK) {
            std.debug.print("Warning: Failed to set RSA key\n", .{});
        } else {
            std.debug.print("RSA key set successfully\n", .{});
        }
        
        // Try to set ECDSA key
        const ecdsa_key_path = "tmp_keys/ssh_host_ecdsa_key";
        if (ssh_bind_options_set(bind, SSH_BIND_OPTIONS_ECDSAKEY, ecdsa_key_path) != SSH_OK) {
            std.debug.print("Warning: Failed to set ECDSA key\n", .{});
        } else {
            std.debug.print("ECDSA key set successfully\n", .{});
        }
        
        return SSHServer{
            .allocator = allocator,
            .bind = bind,
            .host = host,
            .port = port,
        };
    }
    
    pub fn deinit(self: *SSHServer) void {
        ssh_bind_free(self.bind);
        _ = ssh_finalize();
    }
    
    pub fn listen(self: *SSHServer) !void {
        std.debug.print("Starting SSH bind listen...\n", .{});
        const result = ssh_bind_listen(self.bind);
        if (result != SSH_OK) {
            std.debug.print("SSH bind listen failed with code: {}\n", .{result});
            
            // Try to get more specific error information
            const error_msg = ssh_get_error_bind(self.bind);
            std.debug.print("SSH bind error: {s}\n", .{error_msg});
            
            return error.SSHBindListenFailed;
        }
        std.debug.print("SSH bind listen successful\n", .{});
    }
    
    pub fn accept(self: *SSHServer) !SSHConnection {
        const session = ssh_new() orelse {
            return error.SSHSessionCreateFailed;
        };
        
        if (ssh_bind_accept(self.bind, session) != SSH_OK) {
            ssh_free(session);
            return error.SSHBindAcceptFailed;
        }
        
        return SSHConnection{
            .allocator = self.allocator,
            .session = session,
        };
    }
};

pub const SSHConnection = struct {
    allocator: std.mem.Allocator,
    session: *SSHSession,
    
    pub fn deinit(self: *SSHConnection) void {
        ssh_free(self.session);
    }
    
    pub fn handleKeyExchange(self: *SSHConnection) !void {
        if (ssh_handle_key_exchange(self.session) != SSH_OK) {
            const error_msg = ssh_get_error(self.session);
            std.debug.print("SSH key exchange failed: {s}\n", .{error_msg});
            return error.SSHKeyExchangeFailed;
        }
    }
    
    pub fn processMessages(self: *SSHConnection, message_handler: *const fn(*SSHMessage) void) !void {
        while (true) {
            const msg = ssh_message_get(self.session) orelse break;
            defer ssh_message_free(msg);
            
            message_handler(msg);
        }
    }
};

// Helper functions for message handling
pub fn handleAuthMessage(msg: *SSHMessage) bool {
    const msg_type = ssh_message_type(msg);
    const msg_subtype = ssh_message_subtype(msg);
    
    if (msg_type == SSH_REQUEST_AUTH) {
        if (msg_subtype == SSH_AUTH_METHOD_PASSWORD) {
            const user = ssh_message_auth_user(msg);
            const password = ssh_message_auth_password(msg);
            
            std.debug.print("Authentication attempt: user={s}, password={s}\n", .{ user, password });
            
            // For demo purposes, accept any user/password
            // In production, implement proper authentication
            if (ssh_message_auth_reply_success(msg, 0) == SSH_OK) {
                std.debug.print("Authentication successful\n", .{});
                return true;
            }
        }
        
        // Reject authentication
        _ = ssh_message_auth_reply_default(msg);
    }
    
    return false;
}

pub fn handleChannelMessage(msg: *SSHMessage) ?*SSHChannel {
    const msg_type = ssh_message_type(msg);
    const msg_subtype = ssh_message_subtype(msg);
    
    if (msg_type == SSH_REQUEST_CHANNEL_OPEN) {
        if (msg_subtype == SSH_CHANNEL_SESSION) {
            std.debug.print("Channel open request received\n", .{});
            return ssh_message_channel_request_open_reply_accept(msg);
        }
    } else if (msg_type == SSH_REQUEST_CHANNEL) {
        if (msg_subtype == SSH_CHANNEL_REQUEST_SHELL or msg_subtype == SSH_CHANNEL_REQUEST_PTY) {
            std.debug.print("Channel request: shell/pty\n", .{});
            _ = ssh_message_channel_request_reply_success(msg);
            return null; // Channel already established
        }
    }
    
    return null;
}
