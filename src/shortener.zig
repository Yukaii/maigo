const std = @import("std");
const testing = std.testing;

const BASE62_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BASE62_LEN = BASE62_CHARS.len;

pub const ShortCode = struct {
    code: []const u8,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, code: []const u8) !ShortCode {
        const owned_code = try allocator.dupe(u8, code);
        return ShortCode{
            .code = owned_code,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ShortCode) void {
        self.allocator.free(self.code);
    }
};

pub const Shortener = struct {
    allocator: std.mem.Allocator,
    rng: std.Random.DefaultPrng,

    pub fn init(allocator: std.mem.Allocator) Shortener {
        const rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            std.crypto.random.bytes(std.mem.asBytes(&seed));
            break :blk seed;
        });

        return Shortener{
            .allocator = allocator,
            .rng = rng,
        };
    }

    pub fn encodeId(self: *Shortener, id: u64) !ShortCode {
        if (id == 0) {
            return ShortCode.init(self.allocator, "0");
        }

        var result = std.ArrayList(u8).init(self.allocator);
        defer result.deinit();

        var num = id;
        while (num > 0) {
            const remainder = num % BASE62_LEN;
            try result.append(BASE62_CHARS[remainder]);
            num /= BASE62_LEN;
        }

        std.mem.reverse(u8, result.items);
        return ShortCode.init(self.allocator, result.items);
    }

    pub fn decodeId(code: []const u8) !u64 {
        var result: u64 = 0;
        var power: u64 = 1;

        var i = code.len;
        while (i > 0) {
            i -= 1;
            const char = code[i];
            
            const digit = for (BASE62_CHARS, 0..) |c, idx| {
                if (c == char) break idx;
            } else return error.InvalidCharacter;

            result += @as(u64, @intCast(digit)) * power;
            power *= BASE62_LEN;
        }

        return result;
    }

    pub fn generateRandom(self: *Shortener, length: usize) !ShortCode {
        const code = try self.allocator.alloc(u8, length);
        
        for (code) |*c| {
            const idx = self.rng.random().uintLessThan(usize, BASE62_LEN);
            c.* = BASE62_CHARS[idx];
        }

        return ShortCode{
            .code = code,
            .allocator = self.allocator,
        };
    }

    pub fn isValidCode(code: []const u8) bool {
        if (code.len == 0) return false;
        
        for (code) |c| {
            const valid = for (BASE62_CHARS) |valid_char| {
                if (c == valid_char) break true;
            } else false;
            
            if (!valid) return false;
        }
        
        return true;
    }
};

test "encode and decode id" {
    var shortener = Shortener.init(testing.allocator);
    
    const test_cases = [_]u64{ 0, 1, 61, 62, 123, 999999 };
    
    for (test_cases) |id| {
        var short_code = try shortener.encodeId(id);
        defer short_code.deinit();
        
        const decoded = try Shortener.decodeId(short_code.code);
        try testing.expectEqual(id, decoded);
    }
}

test "generate random code" {
    var shortener = Shortener.init(testing.allocator);
    
    var code1 = try shortener.generateRandom(6);
    defer code1.deinit();
    
    var code2 = try shortener.generateRandom(6);
    defer code2.deinit();
    
    try testing.expect(code1.code.len == 6);
    try testing.expect(code2.code.len == 6);
    try testing.expect(!std.mem.eql(u8, code1.code, code2.code));
}

test "validate code" {
    try testing.expect(Shortener.isValidCode("abc123"));
    try testing.expect(Shortener.isValidCode("0"));
    try testing.expect(Shortener.isValidCode("Z"));
    try testing.expect(!Shortener.isValidCode(""));
    try testing.expect(!Shortener.isValidCode("abc@123"));
    try testing.expect(!Shortener.isValidCode("hello world"));
}

test "base62 encoding properties" {
    var shortener = Shortener.init(testing.allocator);
    
    var code1 = try shortener.encodeId(1);
    defer code1.deinit();
    try testing.expectEqualStrings("1", code1.code);
    
    var code61 = try shortener.encodeId(61);
    defer code61.deinit();
    try testing.expectEqualStrings("z", code61.code);
    
    var code62 = try shortener.encodeId(62);
    defer code62.deinit();
    try testing.expectEqualStrings("10", code62.code);
}