# Maigo Core API

The API is designed for one trusted owner. Redirects and link metadata are
public; link management uses the installation API key.

## Authentication

Send either header on protected requests:

```text
Authorization: Bearer <API_KEY>
X-Maigo-API-Key: <API_KEY>
```

There are no user accounts, browser login, OAuth endpoints, JWTs, refresh
tokens, or sessions in Core.

## Endpoints

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/health` | no | Liveness |
| GET | `/health/ready` | no | Liveness plus SQLite readiness |
| POST | `/api/v1/urls` | yes | Create a short link |
| GET | `/api/v1/urls` | yes | List all links |
| GET | `/api/v1/urls/{code}` | no | Inspect public metadata |
| GET | `/api/v1/urls/{code}/stats` | yes | Read lifetime hits |
| DELETE | `/api/v1/urls/{code}` | yes | Delete a link |
| GET | `/{code}` | no | Redirect and count one hit |

## Create a link

```bash
curl -X POST http://127.0.0.1:8080/api/v1/urls \
  -H 'X-Maigo-API-Key: dev_maigo_api_key_change_me' \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com","custom":"home","ttl":86400}'
```

`url` accepts HTTP(S) URLs; a missing scheme is treated as HTTPS. `custom` is
an optional Base62 alias; the reserved root paths `api` and `health` cannot be
used. `ttl` is in seconds and must be at least 60. Use
`expires_at` as an RFC3339 timestamp instead of `ttl`; the two fields cannot be
combined. Omitting both creates a link without an expiry.

Successful responses include `short_code`, `short_url`, `target_url`,
`created_at`, `hits`, and optional expiration fields. Duplicate aliases return
HTTP 409. Expired redirects return HTTP 410 and do not increment hits.

## List and statistics

```bash
curl -H 'Authorization: Bearer <API_KEY>' \
  'http://127.0.0.1:8080/api/v1/urls?page=1&page_size=20'

curl -H 'Authorization: Bearer <API_KEY>' \
  http://127.0.0.1:8080/api/v1/urls/home/stats
```

List pages accept `page` and `page_size`; the page size is bounded to 1–100.
Statistics contain the lifetime `hits` value only. Core does not retain a
click-event timeline.

## Errors

Errors use this shape:

```json
{
  "error": "not_found",
  "message": "Short URL not found",
  "details": null
}
```

The authoritative machine-readable contract is
[`openapi.yaml`](openapi.yaml).
