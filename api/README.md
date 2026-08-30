# Maigo API

[`openapi.yaml`](openapi.yaml) is the API contract for the current prototype.
The server listens on `http://localhost:8080` by default.

## Authentication

The CLI uses OAuth 2.0 authorization code flow with mandatory PKCE/S256:

1. Generate a 43–128 character code verifier and its SHA-256, base64url code challenge.
2. Open `/oauth/authorize` with `response_type=code`, `client_id=maigo-cli`,
   a registered localhost callback, `state`, `code_challenge`, and
   `code_challenge_method=S256`.
3. Sign in in the browser and approve the consent page.
4. Exchange the callback code at `/oauth/token` with the same redirect URI and
   code verifier.
5. Send the access token as `Authorization: Bearer <access_token>`.

The bundled CLI performs these steps automatically:

```bash
maigo auth register alice alice@example.com
maigo auth login alice
maigo shorten https://example.com
```

For a manual exchange, the request shape is:

```bash
curl -X POST http://localhost:8080/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=<authorization_code>' \
  --data-urlencode 'client_id=maigo-cli' \
  --data-urlencode 'redirect_uri=http://localhost:8000/callback' \
  --data-urlencode 'code_verifier=<code_verifier>'
```

Access tokens use the configured `JWT_EXPIRATION` (24 hours by default).
Refresh tokens are rotated and invalidated on logout or revocation; clients
must persist the newest refresh token after each refresh.

## URL operations

Create a URL:

```bash
curl -X POST http://localhost:8080/api/v1/urls \
  -H 'Authorization: Bearer <access_token>' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/very/long/url","custom":"mylink","ttl":86400}'
```

List the current user’s URLs:

```bash
curl 'http://localhost:8080/api/v1/user/urls?page=1&page_size=20' \
  -H 'Authorization: Bearer <access_token>'
```

Read metadata or follow a short code:

```bash
curl http://localhost:8080/api/v1/urls/mylink
curl -i http://localhost:8080/mylink
```

Statistics and deletion are owner-only:

```bash
curl http://localhost:8080/api/v1/urls/mylink/stats \
  -H 'Authorization: Bearer <access_token>'

curl -X DELETE http://localhost:8080/api/v1/urls/mylink \
  -H 'Authorization: Bearer <access_token>'
```

`ttl` must be at least 60 seconds. Use either `ttl` or `expires_at`, not both;
an explicit expiration must be in the future. Expired links return HTTP 410
from the redirect endpoint and do not count a hit. URL metadata remains
available and includes `expired: true`.

Each successful, non-expired redirect records a click event and updates the
aggregate `hits` count in one database transaction. The owner-only statistics
endpoint returns `timeline` as UTC calendar-day buckets. It returns an empty
array when no clicks have been recorded. If click persistence is temporarily
unavailable, the redirect still proceeds and the server logs the tracking
failure. Clicks that occurred before this migration cannot be reconstructed,
so a legacy URL’s aggregate `hits` value may be larger than the sum of its
timeline buckets.

## Routes at a glance

- `GET /health` — liveness.
- `GET /health/ready` — liveness plus PostgreSQL and configured Redis readiness.
- `POST /api/v1/auth/register`, `POST /api/v1/auth/login` — JSON auth helpers.
- `POST /api/v1/auth/token` — JSON refresh compatibility endpoint.
- `POST /api/v1/auth/logout` — revoke the current user’s refresh session.
- `GET|POST /oauth/authorize`, `POST /oauth/token`, `POST /oauth/revoke` — OAuth.
- `POST /api/v1/urls` — authenticated creation.
- `GET /api/v1/user/urls` and `GET /api/v1/user/profile` — authenticated user data.
- `GET /api/v1/urls/{code}` — public metadata.
- `GET /api/v1/urls/{code}/stats`, `DELETE /api/v1/urls/{code}` — owner operations.
- `GET /{code}` — public redirect.

URL creation and authentication endpoints are rate limited. With
`REDIS_ENABLED=true`, limits use an atomic Redis-backed fixed window and are
shared across replicas; otherwise a bounded per-client in-process limiter is
used. The in-process mode is not a substitute for an edge/API gateway limiter.

## Error shape

JSON API errors use:

```json
{
  "error": "bad_request",
  "message": "Invalid request parameters",
  "details": null
}
```

OAuth token errors use the same envelope at the HTTP layer, with the OAuth
error code in `error` (for example, `invalid_grant`).

Authentication and URL-creation endpoints may return `429 rate_limit_exceeded`.
When Redis-backed limiting is enabled and Redis is unavailable, the protected
endpoint returns `503 rate_limit_unavailable` instead of bypassing the limit.

## Viewing the OpenAPI file

Open `openapi.yaml` in [Swagger Editor](https://editor.swagger.io/), or run
Swagger UI locally:

```bash
docker run --rm -p 8081:8080 \
  -e SWAGGER_JSON=/api/openapi.yaml \
  -v "$PWD/api:/api" swaggerapi/swagger-ui
```

Then visit <http://localhost:8081>.

## Current limitations

Click events currently have no retention policy. Configure HTTPS, Redis or an
edge limiter for horizontal scale, and a real secret manager for any
deployment beyond local development. See
[`docs/STATUS.md`](../docs/STATUS.md) for the fuller audit and next steps.

## License

MIT License — see [`LICENSE`](../LICENSE).
