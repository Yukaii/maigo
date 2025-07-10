const std = @import("std");
const pg = @import("pg");

pub const PostgresError = error{
    ConnectionFailed,
    QueryFailed,
    InvalidConfig,
    NotFound,
    InvalidData,
};

pub const DatabaseConfig = struct {
    host: []const u8 = "localhost",
    port: u16 = 5432,
    database: []const u8,
    username: []const u8,
    password: []const u8,
    max_connections: u32 = 10,
};

pub const Database = struct {
    pool: *pg.Pool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config: DatabaseConfig) !Database {
        var pool_config = pg.Pool.Config{
            .size = config.max_connections,
            .connect = .{
                .host = config.host,
                .port = config.port,
                .username = config.username,
                .password = config.password,
                .database = config.database,
            },
        };

        const pool = pg.Pool.init(allocator, pool_config) catch |err| {
            std.debug.print("Failed to initialize PostgreSQL pool: {}\n", .{err});
            return PostgresError.ConnectionFailed;
        };

        return Database{
            .pool = pool,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Database) void {
        self.pool.deinit();
    }

    pub fn ping(self: *Database) !void {
        const conn = self.pool.acquire() catch |err| {
            std.debug.print("Failed to acquire connection: {}\n", .{err});
            return PostgresError.ConnectionFailed;
        };
        defer self.pool.release(conn);

        _ = conn.query("SELECT 1", .{}) catch |err| {
            std.debug.print("Failed to ping database: {}\n", .{err});
            return PostgresError.QueryFailed;
        };
    }
};

test "database connection basic test" {
    const allocator = std.testing.allocator;

    // This test requires a running PostgreSQL instance
    // Skip if not available in CI/test environment
    const config = DatabaseConfig{
        .database = "maigo_test",
        .username = "postgres",
        .password = "password",
    };

    var db = Database.init(allocator, config) catch |err| {
        std.debug.print("Skipping PostgreSQL test - database not available: {}\n", .{err});
        return;
    };
    defer db.deinit();

    try db.ping();
}