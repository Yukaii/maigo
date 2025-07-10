const std = @import("std");
const lib = @import("src/root.zig");
const database_pg = lib.database_pg;
const postgres = @import("src/postgres.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("PostgreSQL Database Integration Test\n", .{});
    std.debug.print("=====================================\n\n", .{});

    // Check if PostgreSQL connection parameters are available
    const postgres_host = std.posix.getenv("POSTGRES_HOST") orelse "localhost";
    const postgres_port = std.posix.getenv("POSTGRES_PORT") orelse "5432";
    const postgres_db = std.posix.getenv("POSTGRES_DB") orelse "maigo_test";
    const postgres_user = std.posix.getenv("POSTGRES_USER") orelse "postgres";
    const postgres_password = std.posix.getenv("POSTGRES_PASSWORD") orelse "password";

    std.debug.print("Connection parameters:\n", .{});
    std.debug.print("Host: {s}\n", .{postgres_host});
    std.debug.print("Port: {s}\n", .{postgres_port});
    std.debug.print("Database: {s}\n", .{postgres_db});
    std.debug.print("User: {s}\n", .{postgres_user});
    std.debug.print("Password: {s}\n\n", .{if (postgres_password.len > 0) "[SET]" else "[NOT SET]"});

    const config = postgres.DatabaseConfig{
        .host = postgres_host,
        .port = std.fmt.parseInt(u16, postgres_port, 10) catch 5432,
        .database = postgres_db,
        .username = postgres_user,
        .password = postgres_password,
    };

    var db = database_pg.Database.init(allocator, config) catch |err| {
        std.debug.print("Failed to connect to PostgreSQL: {}\n", .{err});
        std.debug.print("\nTo test PostgreSQL integration, ensure you have:\n", .{});
        std.debug.print("1. PostgreSQL running on localhost:5432\n", .{});
        std.debug.print("2. Database 'maigo_test' created\n", .{});
        std.debug.print("3. User 'postgres' with password 'password'\n", .{});
        std.debug.print("\nOr set environment variables:\n", .{});
        std.debug.print("POSTGRES_HOST=<host>\n", .{});
        std.debug.print("POSTGRES_PORT=<port>\n", .{});
        std.debug.print("POSTGRES_DB=<database>\n", .{});
        std.debug.print("POSTGRES_USER=<username>\n", .{});
        std.debug.print("POSTGRES_PASSWORD=<password>\n", .{});
        return;
    };
    defer db.deinit();

    std.debug.print("✓ Connected to PostgreSQL successfully!\n\n", .{});

    // Test basic database operations
    std.debug.print("Testing database operations:\n", .{});
    std.debug.print("----------------------------\n", .{});

    // Test user creation
    std.debug.print("1. Creating test user...\n", .{});
    const user_id = db.insertUser("testuser", "test@example.com", "hashedpassword123") catch |err| {
        std.debug.print("   Error creating user: {}\n", .{err});
        return;
    };
    std.debug.print("   ✓ User created with ID: {}\n", .{user_id});

    // Test user retrieval
    std.debug.print("2. Retrieving user...\n", .{});
    var user = db.getUserByUsername("testuser") catch |err| {
        std.debug.print("   Error retrieving user: {}\n", .{err});
        return;
    };
    
    if (user) |*u| {
        defer u.deinit(allocator);
        std.debug.print("   ✓ Retrieved user: {s} ({s})\n", .{ u.username, u.email });
    } else {
        std.debug.print("   ✗ User not found\n", .{});
        return;
    }

    // Test CLI client fixture
    std.debug.print("3. Checking CLI client fixture...\n", .{});
    const cli_client = db.getOAuthClient("maigo-cli") catch |err| {
        std.debug.print("   Error retrieving CLI client: {}\n", .{err});
        return;
    };
    
    if (cli_client) |client| {
        std.debug.print("   ✓ CLI client found: {s}\n", .{client.name});
        var mutable_client = client;
        mutable_client.deinit(allocator);
    } else {
        std.debug.print("   ✗ CLI client not found\n", .{});
        return;
    }

    // Test URL operations
    std.debug.print("4. Creating short URL...\n", .{});
    const url_id = db.insertUrl("test123", "https://example.com", user_id) catch |err| {
        std.debug.print("   Error creating URL: {}\n", .{err});
        return;
    };
    std.debug.print("   ✓ URL created with ID: {}\n", .{url_id});

    std.debug.print("5. Retrieving URL...\n", .{});
    var url = db.getUrlByShortCode("test123") catch |err| {
        std.debug.print("   Error retrieving URL: {}\n", .{err});
        return;
    };
    
    if (url) |*u| {
        defer u.deinit(allocator);
        std.debug.print("   ✓ Retrieved URL: {s} -> {s}\n", .{ u.short_code, u.target_url });
        std.debug.print("   ✓ Hits: {}, User ID: {?}\n", .{ u.hits, u.user_id });
    } else {
        std.debug.print("   ✗ URL not found\n", .{});
        return;
    }

    std.debug.print("6. Incrementing hits...\n", .{});
    db.incrementHits("test123") catch |err| {
        std.debug.print("   Error incrementing hits: {}\n", .{err});
        return;
    };

    var updated_url = db.getUrlByShortCode("test123") catch |err| {
        std.debug.print("   Error retrieving updated URL: {}\n", .{err});
        return;
    };
    
    if (updated_url) |*u| {
        defer u.deinit(allocator);
        std.debug.print("   ✓ Updated hits: {}\n", .{u.hits});
    }

    std.debug.print("\n✓ All tests passed! PostgreSQL integration is working correctly.\n", .{});
    std.debug.print("\nNext steps:\n", .{});
    std.debug.print("1. Complete remaining repository methods (auth codes, access tokens)\n", .{});
    std.debug.print("2. Update application to use PostgreSQL configuration\n", .{});
    std.debug.print("3. Add migration tools for existing SQLite data\n", .{});
}