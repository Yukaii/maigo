# Maigo Core 1.0

Maigo Core is a self-hosted shortener for one owner or one small trusted
installation. Its job is deliberately narrow:

- create short links, including optional custom aliases;
- expire links when requested;
- redirect links and keep a lifetime hit count;
- list, inspect, report, and delete links through the JSON API and CLI;
- expose the same operations as a local stdio MCP server.

## Operating model

Core uses one API key, one SQLite database file, and one application container.
The API key protects link management; redirects and public metadata remain
public. `PUBLIC_URL` is the canonical origin used in generated links.

TLS and DNS are edge concerns. Point one A/AAAA or CNAME record at the host and
terminate TLS with an existing reverse proxy such as Caddy, Traefik, Cloudflare,
or Tailscale. Maigo does not manage certificates or custom-domain records.

## Explicitly out of scope

OAuth, browser consent pages, user accounts, JWTs, refresh sessions, Redis,
distributed rate limiting, click-event timelines, multi-tenant ownership,
application-managed custom domains, and application-managed TLS are deferred.
They can return in a future edition only when a real use case justifies their
operational cost.

## Stopping point

Core 1.0 is done when a new user can:

1. start the container with a data volume, API key, and public URL;
2. create and manage links from the CLI without a browser or account setup;
3. configure an MCP client to launch `maigo mcp` over stdio;
4. put one DNS record and an ordinary TLS reverse proxy in front of it;
5. back up the SQLite file by copying the mounted data volume; and
6. run the unit and integration suites without PostgreSQL or Redis.

The current production-hardening branch remains available for comparison, but
it is not the target runtime for Core 1.0.
