# Render Single-Yahoo MCP Design

## Goal

Deploy the existing read-only Yahoo Mail MCP server as a Render Node.js web service and connect one main Yahoo mailbox to ChatGPT through a portable, single-user OAuth 2.1 flow. Multi-mailbox support and changes to the existing Morning Brief are explicitly deferred.

## Scope

Phase 1 preserves the existing five read-only tools:

- `get_morning_brief_emails`
- `list_emails`
- `search_emails`
- `read_email`
- `list_folders`

Only one Yahoo mailbox is configured through `YAHOO_EMAIL` and `YAHOO_APP_PASSWORD`. The service never sends, deletes, moves, archives, flags, or marks mail as read. The existing sanitization, output bounds, OTP and sensitive-link redaction, TLS verification, and untrusted-email warnings remain mandatory.

Phase 1 does not aggregate multiple Yahoo accounts, modify the Morning Brief chat, send notifications, or run scheduled jobs. Those are separate follow-on changes after the main mailbox passes an authenticated live smoke test.

## Runtime architecture

The implementation starts from the existing `main` branch Node/Express server rather than porting the Cloudflare Worker runtime back to Node. Render runs one public web service that binds to `0.0.0.0:$PORT` and exposes:

- `GET /health` for a credential-free process health check
- `POST|GET /mcp` for Streamable HTTP MCP traffic
- OAuth discovery, registration, authorization, callback-free login, and token endpoints at the service origin

The MCP request handler remains stateless per request. Yahoo IMAP connections are opened only for tool calls, use TLS on port 993, open mailboxes read-only, and close on success, failure, cancellation, or deadline expiry.

Render Key Value provides the durable, TTL-aware state required for OAuth replay prevention and token rotation. The web service must fail closed when Key Value, OAuth secrets, Yahoo secrets, or the canonical public resource URL are missing.

## Single-user authentication

The service is its own OAuth 2.1 authorization server and resource server. It does not depend on Cloudflare Access, Google, Auth0, or another identity provider.

The owner chooses a private passphrase locally. Only a salted Node `scrypt` digest is stored in Render as `MCP_LOGIN_PASSPHRASE_SCRYPT`; the plaintext passphrase is never committed, logged, sent to ChatGPT, or stored by the service. Authorization presents a minimal HTTPS form. The form uses a secure, HTTP-only, same-site CSRF cookie and a short-lived server-side transaction record. Failed passphrase attempts are rate-limited by IP and authorization transaction without logging the submitted value.

Successful authorization issues an MCP authorization code; it does not expose Yahoo credentials or reuse the Yahoo password. ChatGPT exchanges the code using PKCE. The service accepts bearer tokens only in the `Authorization` header and rejects tokens in query strings.

## OAuth protocol behavior

The implementation provides:

- OAuth Protected Resource Metadata for `/mcp`
- OAuth Authorization Server Metadata at the service origin
- dynamic client registration with strict metadata and redirect-URI validation
- authorization-code grant with required S256 PKCE
- RFC 8707 `resource` validation bound to the canonical `/mcp` URL
- single-use authorization codes with a five-minute lifetime
- opaque access tokens with a fifteen-minute lifetime
- rotating opaque refresh tokens with a thirty-day maximum lifetime
- refresh-token family revocation when a rotated token is replayed

Registered clients, pending authorization transactions, authorization codes, hashed access tokens, refresh-token families, and rate-limit counters are stored under distinct Key Value prefixes. Raw access tokens, refresh tokens, authorization codes, passphrases, Yahoo credentials, and email content are never stored in Key Value or logs. Token and code lookups use SHA-256 digests; equality checks use timing-safe comparisons where applicable.

Dynamic registration accepts only HTTPS redirect URIs, except loopback `http://127.0.0.1` or `http://localhost` callbacks used by local MCP Inspector testing. Redirect URIs must match registered values exactly. Client metadata is bounded in size and count, and registration responses never contain infrastructure or Yahoo secrets.

## Configuration and secrets

The Render web service receives these required secrets:

- `YAHOO_EMAIL`
- `YAHOO_APP_PASSWORD`
- `MCP_LOGIN_PASSPHRASE_SCRYPT`
- `OAUTH_COOKIE_KEY`
- `REDIS_URL`, supplied from the Render Key Value instance

The canonical service origin comes from Render's external URL and is normalized into the exact MCP resource URL ending in `/mcp`. Host and Origin validation allow only the assigned Render host and explicitly configured development origins. `ALLOWED_HOSTS` remains fail-closed for production.

Secrets are entered through Render environment-variable controls or generated locally through hidden input. They are never pasted into chat, committed, printed, included in deployment output, or exposed by `/health`.

## Error handling and observability

Public OAuth and MCP errors use stable, secret-free error codes. Logs may contain a request ID, endpoint, OAuth stage, status class, and account-neutral operation name. Logs must not contain tokens, authorization codes, redirect query strings, passphrases, Yahoo credentials, email addresses, subjects, senders, bodies, folder names, or IMAP server responses that can contain mailbox data.

Failure of Key Value, token validation, configuration, or Yahoo authentication denies access. `/health` proves only that the Node process is serving HTTP. A separate authenticated smoke test verifies mailbox connectivity without returning message content.

## Render deployment

The repository already has a GitHub remote and a Render-ready Node/Express implementation on `main`. A dedicated implementation branch will add OAuth, Key Value support, tests, and Render configuration. The Render deployment is one web service plus one Key Value instance in the same region.

No Render resources are created until the implementation is verified and the user approves the selected service and Key Value plans. The Blueprint pins the web service to `codex/render-single-yahoo-mcp`: auto-deploy begins only after the reviewed commit is pushed there, and continues to deploy that reviewed branch/commit until an explicit, separately reviewed merge-and-branch-switch change updates the Blueprint. The web service uses `npm ci`, `npm run build`, and `npm start`, with `/health` as the health-check path.

## Verification

Automated verification must cover:

- configuration fails closed when any required secret or canonical URL is absent
- unauthenticated `/mcp` returns `401` with correct protected-resource metadata
- discovery documents advertise PKCE S256 and the exact resource URL
- dynamic registration rejects unsafe or mismatched redirect URIs
- CSRF mismatch and passphrase failure deny authorization
- authorization codes are short-lived, PKCE-bound, and single-use
- access tokens are audience-bound, expire, and are never accepted from query strings
- refresh tokens rotate and replay revokes their family
- OAuth values and mailbox data do not appear in logs or public errors
- all five tools remain read-only and preserve current sanitization limits
- Yahoo connections close on success, failure, timeout, and cancellation

Production verification proceeds in this order: `/health`, unauthenticated `/mcp`, OAuth discovery, MCP Inspector authorization, five-tool discovery, `list_folders`, and one bounded `get_morning_brief_emails` call. The smoke test reports only success or a sanitized failure; it does not retain or print mailbox data.

## Follow-on work

After Phase 1 is live and verified, a separate design can add three named Yahoo accounts, partial-failure aggregation, per-account selectors, and an update to the existing Morning Brief chat. None of that is required for this deployment to be considered complete.
