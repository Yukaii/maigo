# Maigo API Documentation

This directory contains the OpenAPI 3.0 specification for the Maigo URL Shortener API.

## Viewing the Documentation

### Online Swagger Editor

1. Open [Swagger Editor](https://editor.swagger.io/)
2. Go to **File > Import File**
3. Select `openapi.yaml` from this directory

### Local Swagger UI (Docker)

```bash
# From the project root
docker run -p 8081:8080 \
  -e SWAGGER_JSON=/api/openapi.yaml \
  -v $(pwd)/api:/api \
  swaggerapi/swagger-ui
```

Then open http://localhost:8081 in your browser.

### Using Redoc

```bash
# Install redoc-cli globally
npm install -g redoc-cli

# Generate static HTML documentation
redoc-cli bundle api/openapi.yaml -o api/docs.html

# Or serve it locally
redoc-cli serve api/openapi.yaml --port 8081
```

## API Overview

The Maigo API provides:

- **OAuth 2.0 Authentication** with PKCE support for CLI clients
- **URL Shortening** with custom codes and expiration support
- **URL Management** (create, list, get, delete)
- **Health Checks** for monitoring
- **User Management** (registration, login, profile)

## Authentication Flow

### OAuth 2.0 Authorization Code Flow with PKCE

1. **Generate PKCE parameters**: Create a code verifier and challenge
2. **Authorization Request**: Redirect to `/oauth/authorize` with PKCE challenge
3. **User Authorization**: User approves/denies the request
4. **Authorization Callback**: Receive authorization code
5. **Token Exchange**: Exchange code for tokens at `/oauth/token` with PKCE verifier
6. **API Requests**: Use access token in `Authorization: Bearer <token>` header
7. **Token Refresh**: Use refresh token to get new access tokens

### Example CLI Flow

```bash
# 1. CLI generates PKCE parameters
code_verifier=$(openssl rand -base64 96 | tr -d '\n' | tr -d '=' | tr '+/' '-_')
code_challenge=$(echo -n "$code_verifier" | openssl dgst -binary -sha256 | base64 | tr -d '\n' | tr -d '=' | tr '+/' '-_')

# 2. Open browser to authorization URL
open "http://localhost:8080/oauth/authorize?response_type=code&client_id=maigo-cli&redirect_uri=http://localhost:8000/callback&state=random_state&code_challenge=$code_challenge&code_challenge_method=S256"

# 3. User approves, receives code in callback
# authorization_code=<received_code>

# 4. Exchange code for tokens
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$authorization_code" \
  -d "client_id=maigo-cli" \
  -d "redirect_uri=http://localhost:8000/callback" \
  -d "code_verifier=$code_verifier"

# 5. Use access token for API requests
curl http://localhost:8080/api/v1/urls \
  -H "Authorization: Bearer <access_token>"
```

## Quick Start Examples

### Create Short URL

```bash
curl -X POST http://localhost:8080/api/v1/urls \
  -H "Authorization: Bearer <access_token>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/very/long/url",
    "custom": "mylink",
    "ttl": 86400
  }'
```

### List URLs

```bash
curl http://localhost:8080/api/v1/urls?page=1&limit=20 \
  -H "Authorization: Bearer <access_token>"
```

### Redirect via Short Code

```bash
curl -L http://localhost:8080/abc123
```

### Refresh Access Token

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<refresh_token>" \
  -d "client_id=maigo-cli"
```

## Error Handling

All errors follow a consistent format:

```json
{
  "error": "error_code",
  "message": "Human-readable error message",
  "details": "Optional additional details"
}
```

### OAuth 2.0 Errors

OAuth endpoints return standard OAuth 2.0 error codes:

- `invalid_request` - The request is missing a required parameter
- `invalid_client` - Client authentication failed
- `invalid_grant` - Invalid authorization code or refresh token
- `unauthorized_client` - Client not authorized for this grant type
- `unsupported_grant_type` - Grant type not supported
- `invalid_scope` - Invalid or unknown scope

### API Error Codes

- `bad_request` - Invalid request parameters
- `unauthorized` - Authentication required or failed
- `forbidden` - Access denied (insufficient permissions)
- `not_found` - Resource not found
- `conflict` - Resource already exists
- `internal_server_error` - Server error

## Rate Limiting

Currently no rate limiting is enforced. This may be added in future versions.

## Pagination

List endpoints support pagination with query parameters:

- `page` - Page number (default: 1)
- `limit` - Items per page (default: 20, max: 100)

Response includes pagination metadata:

```json
{
  "urls": [...],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

## URL Expiration

URLs can have optional expiration using either:

1. **TTL (Time To Live)**: Relative expiration in seconds
   ```json
   { "url": "https://example.com", "ttl": 86400 }
   ```

2. **Exact Timestamp**: Absolute expiration time
   ```json
   { "url": "https://example.com", "expires_at": "2025-12-31T23:59:59Z" }
   ```

Expired URLs return HTTP 410 Gone when accessed.

## Security Considerations

1. **PKCE Required**: All CLI OAuth flows must use PKCE for security
2. **HTTPS in Production**: Always use HTTPS in production environments
3. **Token Storage**: Store tokens securely (e.g., encrypted local storage)
4. **Token Expiration**: Access tokens expire after 1 hour by default
5. **Refresh Tokens**: Use refresh tokens to obtain new access tokens

## Development

To update the API documentation:

1. Edit `openapi.yaml`
2. Validate the spec: https://editor.swagger.io/
3. Test with the API to ensure accuracy
4. Commit changes to version control

## License

MIT License - See LICENSE file for details
