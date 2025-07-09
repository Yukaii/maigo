const std = @import("std");
const testing = std.testing;
const database = @import("database.zig");

pub const OAuthError = error{
    InvalidClient,
    InvalidGrant,
    InvalidRequest,
    InvalidScope,
    UnauthorizedClient,
    UnsupportedGrantType,
    TokenExpired,
    InvalidToken,
};

pub const GrantType = enum {
    authorization_code,
    refresh_token,
    client_credentials,
    
    pub fn fromString(str: []const u8) ?GrantType {
        if (std.mem.eql(u8, str, "authorization_code")) return .authorization_code;
        if (std.mem.eql(u8, str, "refresh_token")) return .refresh_token;
        if (std.mem.eql(u8, str, "client_credentials")) return .client_credentials;
        return null;
    }
};

pub const ResponseType = enum {
    code,
    token,
    
    pub fn fromString(str: []const u8) ?ResponseType {
        if (std.mem.eql(u8, str, "code")) return .code;
        if (std.mem.eql(u8, str, "token")) return .token;
        return null;
    }
};

pub const OAuthClient = struct {
    id: []const u8,
    secret: []const u8,
    redirect_uri: []const u8,
    name: []const u8,
    
    pub fn deinit(self: *OAuthClient, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.secret);
        allocator.free(self.redirect_uri);
        allocator.free(self.name);
    }
};

pub const AuthorizationCode = struct {
    code: []const u8,
    client_id: []const u8,
    user_id: u64,
    redirect_uri: []const u8,
    expires_at: i64,
    used: bool,
    
    pub fn deinit(self: *AuthorizationCode, allocator: std.mem.Allocator) void {
        allocator.free(self.code);
        allocator.free(self.client_id);
        allocator.free(self.redirect_uri);
    }
};

pub const AccessToken = struct {
    token: []const u8,
    client_id: []const u8,
    user_id: u64,
    scope: []const u8,
    expires_at: i64,
    refresh_token: ?[]const u8,
    
    pub fn deinit(self: *AccessToken, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
        allocator.free(self.client_id);
        allocator.free(self.scope);
        if (self.refresh_token) |rt| {
            allocator.free(rt);
        }
    }
};

pub const AuthorizeRequest = struct {
    response_type: ResponseType,
    client_id: []const u8,
    redirect_uri: []const u8,
    scope: []const u8,
    state: ?[]const u8,
    
    pub fn deinit(self: *AuthorizeRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.client_id);
        allocator.free(self.redirect_uri);
        allocator.free(self.scope);
        if (self.state) |s| {
            allocator.free(s);
        }
    }
};

pub const TokenRequest = struct {
    grant_type: GrantType,
    client_id: []const u8,
    client_secret: []const u8,
    code: ?[]const u8,
    redirect_uri: ?[]const u8,
    refresh_token: ?[]const u8,
    
    pub fn deinit(self: *TokenRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.client_id);
        allocator.free(self.client_secret);
        if (self.code) |c| allocator.free(c);
        if (self.redirect_uri) |r| allocator.free(r);
        if (self.refresh_token) |rt| allocator.free(rt);
    }
};

pub const OAuthServer = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    rng: std.Random.DefaultPrng,
    
    pub fn init(allocator: std.mem.Allocator, db: *database.Database) OAuthServer {
        const rng = std.Random.DefaultPrng.init(blk: {
            var seed: u64 = undefined;
            std.crypto.random.bytes(std.mem.asBytes(&seed));
            break :blk seed;
        });
        
        return OAuthServer{
            .allocator = allocator,
            .db = db,
            .rng = rng,
        };
    }
    
    pub fn createClient(self: *OAuthServer, name: []const u8, redirect_uri: []const u8) !OAuthClient {
        const client_id = try self.generateRandomString(32);
        const client_secret = try self.generateRandomString(64);
        
        // TODO: Store client in database
        
        return OAuthClient{
            .id = client_id,
            .secret = client_secret,
            .redirect_uri = try self.allocator.dupe(u8, redirect_uri),
            .name = try self.allocator.dupe(u8, name),
        };
    }
    
    pub fn authorize(self: *OAuthServer, request: AuthorizeRequest, user_id: u64) ![]const u8 {
        // Validate client
        var client = try self.getClient(request.client_id) orelse return OAuthError.InvalidClient;
        defer client.deinit(self.allocator);
        
        // Validate redirect URI
        if (!std.mem.eql(u8, client.redirect_uri, request.redirect_uri)) {
            return OAuthError.InvalidClient;
        }
        
        switch (request.response_type) {
            .code => {
                // Generate authorization code
                const code = try self.generateRandomString(32);
                const expires_at = std.time.timestamp() + 600; // 10 minutes
                
                const auth_code = AuthorizationCode{
                    .code = code,
                    .client_id = try self.allocator.dupe(u8, request.client_id),
                    .user_id = user_id,
                    .redirect_uri = try self.allocator.dupe(u8, request.redirect_uri),
                    .expires_at = expires_at,
                    .used = false,
                };
                
                try self.storeAuthorizationCode(auth_code);
                
                return code;
            },
            .token => {
                // Direct token grant (implicit flow)
                return self.generateAccessToken(request.client_id, user_id, request.scope);
            },
        }
    }
    
    pub fn exchangeCodeForToken(self: *OAuthServer, request: TokenRequest) !AccessToken {
        switch (request.grant_type) {
            .authorization_code => return self.handleAuthorizationCodeGrant(request),
            .refresh_token => return self.handleRefreshTokenGrant(request),
            else => return OAuthError.UnsupportedGrantType,
        }
    }
    
    fn handleAuthorizationCodeGrant(self: *OAuthServer, request: TokenRequest) !AccessToken {
        
        const code = request.code orelse return OAuthError.InvalidRequest;
        const redirect_uri = request.redirect_uri orelse return OAuthError.InvalidRequest;
        
        // Validate client
        var client = try self.getClient(request.client_id) orelse return OAuthError.InvalidClient;
        defer client.deinit(self.allocator);
        
        if (!std.mem.eql(u8, client.secret, request.client_secret)) {
            return OAuthError.InvalidClient;
        }
        
        // Get and validate authorization code
        var auth_code = try self.getAuthorizationCode(code) orelse return OAuthError.InvalidGrant;
        defer auth_code.deinit(self.allocator);
        
        if (auth_code.used) {
            return OAuthError.InvalidGrant;
        }
        
        if (std.time.timestamp() > auth_code.expires_at) {
            return OAuthError.InvalidGrant;
        }
        
        if (!std.mem.eql(u8, auth_code.client_id, request.client_id)) {
            return OAuthError.InvalidGrant;
        }
        
        if (!std.mem.eql(u8, auth_code.redirect_uri, redirect_uri)) {
            return OAuthError.InvalidGrant;
        }
        
        // Mark code as used
        try self.markAuthorizationCodeUsed(code);
        
        // Generate access token
        const access_token = try self.generateRandomString(64);
        const refresh_token = try self.generateRandomString(64);
        const expires_at = std.time.timestamp() + 3600; // 1 hour
        
        const token = AccessToken{
            .token = access_token,
            .client_id = try self.allocator.dupe(u8, request.client_id),
            .user_id = auth_code.user_id,
            .scope = try self.allocator.dupe(u8, "url:write url:read"),
            .expires_at = expires_at,
            .refresh_token = refresh_token,
        };
        
        try self.storeAccessToken(token);
        
        return token;
    }
    
    fn handleRefreshTokenGrant(self: *OAuthServer, request: TokenRequest) !AccessToken {
        const refresh_token = request.refresh_token orelse return OAuthError.InvalidRequest;
        
        // Validate client
        var client = try self.getClient(request.client_id) orelse return OAuthError.InvalidClient;
        defer client.deinit(self.allocator);
        
        if (!std.mem.eql(u8, client.secret, request.client_secret)) {
            return OAuthError.InvalidClient;
        }
        
        // Find existing token by refresh token
        const existing_token = try self.getAccessTokenByRefresh(refresh_token) orelse return OAuthError.InvalidGrant;
        defer {
            self.allocator.free(existing_token.token);
            self.allocator.free(existing_token.client_id);
            self.allocator.free(existing_token.scope);
            if (existing_token.refresh_token) |rt| {
                self.allocator.free(rt);
            }
        }
        
        // Validate token hasn't expired (refresh tokens have longer expiration)
        if (std.time.timestamp() > existing_token.expires_at + 7 * 24 * 3600) { // 7 days
            return OAuthError.InvalidGrant;
        }
        
        // Generate new access token
        const new_access_token = try self.generateRandomString(64);
        const new_refresh_token = try self.generateRandomString(64);
        const expires_at = std.time.timestamp() + 3600; // 1 hour
        
        // Revoke old token
        try self.revokeAccessToken(existing_token.token);
        
        // Create new token
        const token = AccessToken{
            .token = new_access_token,
            .client_id = try self.allocator.dupe(u8, request.client_id),
            .user_id = existing_token.user_id,
            .scope = try self.allocator.dupe(u8, existing_token.scope),
            .expires_at = expires_at,
            .refresh_token = new_refresh_token,
        };
        
        try self.storeAccessToken(token);
        
        return token;
    }
    
    pub fn validateToken(self: *OAuthServer, token: []const u8) !?AccessToken {
        const access_token = try self.getAccessToken(token) orelse return null;
        
        if (std.time.timestamp() > access_token.expires_at) {
            return OAuthError.TokenExpired;
        }
        
        return access_token;
    }
    
    fn generateRandomString(self: *OAuthServer, length: usize) ![]u8 {
        const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        const result = try self.allocator.alloc(u8, length);
        
        for (result) |*c| {
            const idx = self.rng.random().uintLessThan(usize, charset.len);
            c.* = charset[idx];
        }
        
        return result;
    }
    
    fn generateAccessToken(self: *OAuthServer, client_id: []const u8, user_id: u64, scope: []const u8) ![]const u8 {
        _ = client_id;
        _ = user_id;
        _ = scope;
        
        return try self.generateRandomString(64);
    }
    
    // Database operations
    fn getClient(self: *OAuthServer, client_id: []const u8) !?OAuthClient {
        const client_data = try self.db.getOAuthClient(client_id) orelse return null;
        
        return OAuthClient{
            .id = client_data.id,
            .secret = client_data.secret,
            .redirect_uri = client_data.redirect_uri,
            .name = client_data.name,
        };
    }
    
    fn storeAuthorizationCode(self: *OAuthServer, auth_code: AuthorizationCode) !void {
        try self.db.insertAuthorizationCode(
            auth_code.code,
            auth_code.client_id,
            auth_code.user_id,
            auth_code.redirect_uri,
            auth_code.expires_at
        );
    }
    
    fn getAuthorizationCode(self: *OAuthServer, code: []const u8) !?AuthorizationCode {
        const code_data = try self.db.getAuthorizationCode(code) orelse return null;
        
        return AuthorizationCode{
            .code = code_data.code,
            .client_id = code_data.client_id,
            .user_id = code_data.user_id,
            .redirect_uri = code_data.redirect_uri,
            .expires_at = code_data.expires_at,
            .used = code_data.used,
        };
    }
    
    fn markAuthorizationCodeUsed(self: *OAuthServer, code: []const u8) !void {
        try self.db.markAuthorizationCodeUsed(code);
    }
    
    fn storeAccessToken(self: *OAuthServer, token: AccessToken) !void {
        try self.db.insertAccessToken(
            token.token,
            token.client_id,
            token.user_id,
            token.scope,
            token.expires_at,
            token.refresh_token
        );
    }
    
    fn getAccessToken(self: *OAuthServer, token: []const u8) !?AccessToken {
        const token_data = try self.db.getAccessToken(token) orelse return null;
        
        return AccessToken{
            .token = token_data.token,
            .client_id = token_data.client_id,
            .user_id = token_data.user_id,
            .scope = token_data.scope,
            .expires_at = token_data.expires_at,
            .refresh_token = token_data.refresh_token,
        };
    }
    
    fn getAccessTokenByRefresh(self: *OAuthServer, refresh_token: []const u8) !?AccessToken {
        const token_data = try self.db.getAccessTokenByRefresh(refresh_token) orelse return null;
        
        return AccessToken{
            .token = token_data.token,
            .client_id = token_data.client_id,
            .user_id = token_data.user_id,
            .scope = token_data.scope,
            .expires_at = token_data.expires_at,
            .refresh_token = token_data.refresh_token,
        };
    }
    
    fn revokeAccessToken(self: *OAuthServer, token: []const u8) !void {
        try self.db.revokeAccessToken(token);
    }
};

test "oauth server basic operations" {
    const allocator = testing.allocator;
    
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    
    var oauth_server = OAuthServer.init(allocator, &db);
    
    // Test client creation
    var client = try oauth_server.createClient("Test App", "http://localhost:3000/callback");
    defer client.deinit(allocator);
    
    try testing.expect(client.id.len == 32);
    try testing.expect(client.secret.len == 64);
    try testing.expectEqualStrings("Test App", client.name);
    try testing.expectEqualStrings("http://localhost:3000/callback", client.redirect_uri);
    
    // Store client in database
    try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
    
    // Test client lookup
    const retrieved_client = try oauth_server.getClient(client.id);
    try testing.expect(retrieved_client != null);
    
    var retrieved = retrieved_client.?;
    defer retrieved.deinit(allocator);
    
    try testing.expectEqualStrings(client.id, retrieved.id);
    try testing.expectEqualStrings(client.secret, retrieved.secret);
    try testing.expectEqualStrings(client.name, retrieved.name);
    try testing.expectEqualStrings(client.redirect_uri, retrieved.redirect_uri);
}

test "oauth authorization code flow" {
    const allocator = testing.allocator;
    
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    
    var oauth_server = OAuthServer.init(allocator, &db);
    
    // Create a test client
    var client = try oauth_server.createClient("Test App", "http://localhost:3000/callback");
    defer client.deinit(allocator);
    
    try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
    
    // Create a test user
    const user_id = try db.insertUser("testuser", "test@example.com");
    
    // Create authorization request
    var auth_request = AuthorizeRequest{
        .response_type = .code,
        .client_id = try allocator.dupe(u8, client.id),
        .redirect_uri = try allocator.dupe(u8, client.redirect_uri),
        .scope = try allocator.dupe(u8, "url:read url:write"),
        .state = try allocator.dupe(u8, "test_state"),
    };
    defer auth_request.deinit(allocator);
    
    // Test authorization
    const auth_code = try oauth_server.authorize(auth_request, user_id);
    defer allocator.free(auth_code);
    
    try testing.expect(auth_code.len == 32);
    
    // Create token request
    var token_request = TokenRequest{
        .grant_type = .authorization_code,
        .client_id = try allocator.dupe(u8, client.id),
        .client_secret = try allocator.dupe(u8, client.secret),
        .code = try allocator.dupe(u8, auth_code),
        .redirect_uri = try allocator.dupe(u8, client.redirect_uri),
        .refresh_token = null,
    };
    defer token_request.deinit(allocator);
    
    // Exchange code for token
    var access_token = try oauth_server.exchangeCodeForToken(token_request);
    defer access_token.deinit(allocator);
    
    try testing.expect(access_token.token.len == 64);
    try testing.expect(access_token.user_id == user_id);
    try testing.expectEqualStrings(client.id, access_token.client_id);
    try testing.expect(access_token.refresh_token != null);
    try testing.expect(access_token.refresh_token.?.len == 64);
    
    // Test token validation
    const validated_token = try oauth_server.validateToken(access_token.token);
    try testing.expect(validated_token != null);
    
    var validated = validated_token.?;
    defer validated.deinit(allocator);
    
    try testing.expectEqualStrings(access_token.token, validated.token);
    try testing.expect(validated.user_id == user_id);
}

test "oauth error cases" {
    const allocator = testing.allocator;
    
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    
    var oauth_server = OAuthServer.init(allocator, &db);
    
    // Test invalid client
    var invalid_request = AuthorizeRequest{
        .response_type = .code,
        .client_id = try allocator.dupe(u8, "invalid_client"),
        .redirect_uri = try allocator.dupe(u8, "http://localhost:3000/callback"),
        .scope = try allocator.dupe(u8, "url:read"),
        .state = null,
    };
    defer invalid_request.deinit(allocator);
    
    const auth_result = oauth_server.authorize(invalid_request, 1);
    try testing.expectError(OAuthError.InvalidClient, auth_result);
    
    // Test invalid grant
    var invalid_token_request = TokenRequest{
        .grant_type = .authorization_code,
        .client_id = try allocator.dupe(u8, "invalid_client"),
        .client_secret = try allocator.dupe(u8, "invalid_secret"),
        .code = try allocator.dupe(u8, "invalid_code"),
        .redirect_uri = try allocator.dupe(u8, "http://localhost:3000/callback"),
        .refresh_token = null,
    };
    defer invalid_token_request.deinit(allocator);
    
    const token_result = oauth_server.exchangeCodeForToken(invalid_token_request);
    try testing.expectError(OAuthError.InvalidClient, token_result);
}

test "grant type parsing" {
    try testing.expect(GrantType.fromString("authorization_code") == .authorization_code);
    try testing.expect(GrantType.fromString("refresh_token") == .refresh_token);
    try testing.expect(GrantType.fromString("client_credentials") == .client_credentials);
    try testing.expect(GrantType.fromString("invalid") == null);
}

test "response type parsing" {
    try testing.expect(ResponseType.fromString("code") == .code);
    try testing.expect(ResponseType.fromString("token") == .token);
    try testing.expect(ResponseType.fromString("invalid") == null);
}

test "oauth refresh token flow" {
    const allocator = testing.allocator;
    
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    
    var oauth_server = OAuthServer.init(allocator, &db);
    
    // Create a test client
    var client = try oauth_server.createClient("Test App", "http://localhost:3000/callback");
    defer client.deinit(allocator);
    
    try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
    
    // Create a test user
    const user_id = try db.insertUser("testuser", "test@example.com");
    
    // Create authorization request
    var auth_request = AuthorizeRequest{
        .response_type = .code,
        .client_id = try allocator.dupe(u8, client.id),
        .redirect_uri = try allocator.dupe(u8, client.redirect_uri),
        .scope = try allocator.dupe(u8, "url:read url:write"),
        .state = null,
    };
    defer auth_request.deinit(allocator);
    
    // Get authorization code
    const auth_code = try oauth_server.authorize(auth_request, user_id);
    defer allocator.free(auth_code);
    
    // Exchange code for initial token
    var initial_token_request = TokenRequest{
        .grant_type = .authorization_code,
        .client_id = try allocator.dupe(u8, client.id),
        .client_secret = try allocator.dupe(u8, client.secret),
        .code = try allocator.dupe(u8, auth_code),
        .redirect_uri = try allocator.dupe(u8, client.redirect_uri),
        .refresh_token = null,
    };
    defer initial_token_request.deinit(allocator);
    
    var initial_token = try oauth_server.exchangeCodeForToken(initial_token_request);
    defer initial_token.deinit(allocator);
    
    try testing.expect(initial_token.refresh_token != null);
    const refresh_token_value = initial_token.refresh_token.?;
    
    // Use refresh token to get new access token
    var refresh_token_request = TokenRequest{
        .grant_type = .refresh_token,
        .client_id = try allocator.dupe(u8, client.id),
        .client_secret = try allocator.dupe(u8, client.secret),
        .code = null,
        .redirect_uri = null,
        .refresh_token = try allocator.dupe(u8, refresh_token_value),
    };
    defer refresh_token_request.deinit(allocator);
    
    var new_token = try oauth_server.exchangeCodeForToken(refresh_token_request);
    defer new_token.deinit(allocator);
    
    // Verify new token is different but has same user_id and scope
    try testing.expect(!std.mem.eql(u8, initial_token.token, new_token.token));
    try testing.expect(initial_token.user_id == new_token.user_id);
    try testing.expectEqualStrings(initial_token.scope, new_token.scope);
    try testing.expect(new_token.refresh_token != null);
    try testing.expect(!std.mem.eql(u8, refresh_token_value, new_token.refresh_token.?));
    
    // Verify old token is revoked and new token is valid
    const old_token_validation = try oauth_server.validateToken(initial_token.token);
    try testing.expect(old_token_validation == null);
    
    const new_token_validation = try oauth_server.validateToken(new_token.token);
    try testing.expect(new_token_validation != null);
    
    var validated = new_token_validation.?;
    defer validated.deinit(allocator);
}

test "oauth token expiration" {
    const allocator = testing.allocator;
    
    var db = try database.Database.init(allocator, ":memory:");
    defer db.deinit();
    
    var oauth_server = OAuthServer.init(allocator, &db);
    
    // Create a test client
    var client = try oauth_server.createClient("Test App", "http://localhost:3000/callback");
    defer client.deinit(allocator);
    
    try db.insertOAuthClient(client.id, client.secret, client.name, client.redirect_uri);
    
    // Create a test user
    const user_id = try db.insertUser("testuser", "test@example.com");
    
    // Create an access token with past expiration
    const expired_token = try oauth_server.generateRandomString(64);
    defer allocator.free(expired_token);
    
    const past_timestamp = std.time.timestamp() - 3600; // 1 hour ago
    
    try db.insertAccessToken(
        expired_token,
        client.id,
        user_id,
        "url:read url:write",
        past_timestamp,
        null
    );
    
    // Test validation of expired token
    const validation_result = oauth_server.validateToken(expired_token);
    try testing.expectError(OAuthError.TokenExpired, validation_result);
    
    // Create a valid token for comparison
    const valid_token = try oauth_server.generateRandomString(64);
    defer allocator.free(valid_token);
    
    const future_timestamp = std.time.timestamp() + 3600; // 1 hour from now
    
    try db.insertAccessToken(
        valid_token,
        client.id,
        user_id,
        "url:read url:write",
        future_timestamp,
        null
    );
    
    // Test validation of valid token
    const valid_result = try oauth_server.validateToken(valid_token);
    try testing.expect(valid_result != null);
    
    var valid_access_token = valid_result.?;
    defer valid_access_token.deinit(allocator);
    
    try testing.expect(valid_access_token.user_id == user_id);
}