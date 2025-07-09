const std = @import("std");
const testing = std.testing;

pub const shortener = @import("shortener.zig");
pub const server = @import("server.zig");
pub const database = @import("database.zig");
pub const oauth = @import("oauth.zig");
pub const libssh_server = @import("libssh_server.zig");

pub export fn add(a: i32, b: i32) i32 {
    return a + b;
}

test "basic add functionality" {
    try testing.expect(add(3, 7) == 10);
}
