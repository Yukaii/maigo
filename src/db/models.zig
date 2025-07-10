const std = @import("std");

pub const Url = struct {
    id: u64,
    short_code: []const u8,
    target_url: []const u8,
    created_at: i64,
    hits: u64,
    user_id: ?u64,

    pub fn deinit(self: *Url, allocator: std.mem.Allocator) void {
        allocator.free(self.short_code);
        allocator.free(self.target_url);
    }
};

pub const User = struct {
    id: u64,
    username: []const u8,
    email: []const u8,
    password_hash: []const u8,
    created_at: i64,

    pub fn deinit(self: *User, allocator: std.mem.Allocator) void {
        allocator.free(self.username);
        allocator.free(self.email);
        allocator.free(self.password_hash);
    }
};

pub const OAuthClient = struct {
    id: []const u8,
    secret: []const u8,
    name: []const u8,
    redirect_uri: []const u8,
    created_at: i64,

    pub fn deinit(self: *OAuthClient, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.secret);
        allocator.free(self.name);
        allocator.free(self.redirect_uri);
    }
};

pub const AuthorizationCode = struct {
    code: []const u8,
    client_id: []const u8,
    user_id: u64,
    redirect_uri: []const u8,
    expires_at: i64,
    used: bool,
    created_at: i64,

    pub fn deinit(self: *AuthorizationCode, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.client_id);
        allocator.free(self.redirect_uri);
    }
};

pub const AccessToken = struct {
    token: []const u8,
    refresh_token: ?[]const u8,
    client_id: []const u8,
    user_id: u64,
    scope: []const u8,
    expires_at: i64,
    created_at: i64,

    pub fn deinit(self: *AccessToken, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        if (self.refresh_token) |rt| {
            allocator.free(rt);
        }
        allocator.free(self.client_id);
        allocator.free(self.scope);
    }
};