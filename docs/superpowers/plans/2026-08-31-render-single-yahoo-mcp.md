# Render Single-Yahoo MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the existing static bearer-token layer with a portable single-user OAuth 2.1 service, retain one read-only Yahoo mailbox, and deploy the Node/Express MCP server as one Render web service backed by Render Key Value.

**Architecture:** The existing Express MCP server remains the resource server and Yahoo IMAP adapter. New focused OAuth modules implement discovery, dynamic registration, passphrase authorization, PKCE code exchange, opaque access tokens, and rotating refresh tokens over a Redis-compatible store. A Render Blueprint provisions the web service and Key Value instance; mailbox and OAuth secrets remain dashboard-managed.

**Tech Stack:** Node.js 20+, TypeScript, Express 5, MCP TypeScript SDK v2, Vitest, Supertest, Node `crypto`, `redis`, Render Web Service, Render Key Value.

**Spec:** `docs/superpowers/specs/2026-08-31-render-single-yahoo-mcp-design.md`

## Global Constraints

- Phase 1 supports exactly one Yahoo mailbox through `YAHOO_EMAIL` and `YAHOO_APP_PASSWORD`.
- Preserve exactly five read-only MCP tools; do not add send, delete, archive, move, flag, or mark-read operations.
- Require OAuth 2.1 authorization code flow with S256 PKCE, RFC 8707 resource binding, dynamic client registration, opaque bearer tokens, and refresh-token rotation.
- Store only token/code SHA-256 digests and bounded metadata in Key Value; never store raw tokens, codes, passphrases, Yahoo credentials, or mailbox content.
- Keep `/health` credential-free and mailbox-free.
- Never print or commit any passphrase, Yahoo app password, OAuth key, token, authorization code, email content, sender, subject, or folder name.
- Multi-account support and Morning Brief changes are out of scope.
- No Render resource creation occurs until code verification passes and the user approves the plan/cost at the deployment gate.

---

### Task 1: Production configuration and testable app boundary

**Files:**

- Modify: `package.json`
- Modify: `src/config.ts`
- Create: `src/app.ts`
- Modify: `src/index.ts`
- Modify: `tests/config-auth.test.ts`
- Create: `tests/app.test.ts`

**Interfaces:**

- Produces: `loadConfig(env): AppConfig` with `redisUrl`, `publicOrigin`, `resourceUrl`, `passphraseDigest`, and `oauthCookieKey`.
- Produces: `createApp(config, dependencies): Express` without opening a listening socket.
- Consumes: the existing `createYahooMcpServer(config)` factory.

- [ ] **Step 1: Add the HTTP-test and Redis dependencies**

Run:

```bash
npm install redis
npm install --save-dev supertest @types/supertest
```

Expected: `package.json` and `package-lock.json` contain `redis`, `supertest`, and `@types/supertest`.

- [ ] **Step 2: Write failing configuration tests**

Add cases to `tests/config-auth.test.ts` using this complete production baseline:

```ts
function validEnv(): NodeJS.ProcessEnv {
  return {
    YAHOO_EMAIL: "user@example.com",
    YAHOO_APP_PASSWORD: "app-password-value",
    REDIS_URL: "redis://127.0.0.1:6379",
    RENDER_EXTERNAL_URL: "https://yahoo-mail-mcp.onrender.com",
    MCP_LOGIN_PASSPHRASE_SCRYPT:
      "scrypt$16384$8$1$c2FsdC1mb3ItdGVzdA$3YQqZrjE8xVgkYMi4Z0ddZ6AiBIrrRD5txi1QGcVPTk",
    OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
    HOST: "0.0.0.0",
    ALLOWED_HOSTS: "yahoo-mail-mcp.onrender.com",
  };
}
```

Assert that missing OAuth/Redis values fail, `PUBLIC_ORIGIN` and `RENDER_EXTERNAL_URL` reject paths/query/HTTP, an explicit `PUBLIC_ORIGIN` overrides the Render value for local tests, and `resourceUrl` equals `https://yahoo-mail-mcp.onrender.com/mcp`.

- [ ] **Step 3: Run the configuration tests to verify failure**

Run:

```bash
npx vitest run tests/config-auth.test.ts
```

Expected: FAIL because the new fields are not parsed and `MCP_API_TOKEN` is still required.

- [ ] **Step 4: Replace static-token configuration with OAuth configuration**

Update `src/config.ts` so the schema requires the four values below and normalizes the origin:

```ts
REDIS_URL: z.string().url(),
PUBLIC_ORIGIN: z.string().url().optional(),
RENDER_EXTERNAL_URL: z.string().url().optional(),
MCP_LOGIN_PASSPHRASE_SCRYPT: z.string().regex(/^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/),
OAUTH_COOKIE_KEY: z.string().min(32),
```

Require at least one origin value, prefer explicit `PUBLIC_ORIGIN` for local/testing overrides, and otherwise use `RENDER_EXTERNAL_URL`. Reject origins whose protocol is not HTTPS or whose pathname, search, username, password, or hash is non-empty. Remove `MCP_API_TOKEN` and return `resourceUrl: new URL('/mcp', publicOrigin).toString()`.

- [ ] **Step 5: Extract Express construction from process startup**

Create `src/app.ts` with these exact seams:

```ts
export interface AppDependencies {
  oauthStore: OAuthStore;
  createMcpServer: (config: AppConfig) => McpServer;
}

export function createApp(
  config: AppConfig,
  dependencies: AppDependencies,
): Express;
```

Move middleware, `/health`, `/mcp`, 404, and error handling out of `src/index.ts`. Leave `src/index.ts` responsible only for loading configuration, connecting Redis, creating the HTTP server, and graceful shutdown.

- [ ] **Step 6: Add and pass an app health test**

Add `tests/app.test.ts`:

```ts
it("serves only process health data", async () => {
  const response = await request(createTestApp()).get("/health");
  expect(response.status).toBe(200);
  expect(response.body).toEqual({ status: "ok" });
  expect(JSON.stringify(response.body)).not.toMatch(
    /yahoo|redis|secret|email/i,
  );
});
```

Run:

```bash
npx vitest run tests/config-auth.test.ts tests/app.test.ts
```

Expected: PASS.

- [ ] **Step 7: Commit the configuration and app boundary**

```bash
git add package.json package-lock.json src/config.ts src/app.ts src/index.ts tests/config-auth.test.ts tests/app.test.ts
git commit -m "refactor: prepare Node server for portable OAuth"
```

---

### Task 2: OAuth cryptography and storage contracts

**Files:**

- Create: `src/oauth/types.ts`
- Create: `src/oauth/crypto.ts`
- Create: `src/oauth/store.ts`
- Create: `src/oauth/redis-store.ts`
- Create: `tests/oauth-crypto.test.ts`
- Create: `tests/oauth-store.test.ts`

**Interfaces:**

- Produces: `sha256Token`, `randomToken`, `verifyPassphrase`, `verifyPkce`, and signed-CSRF helpers.
- Produces: `OAuthStore` and `RedisOAuthStore` with atomic consume/rotate methods.
- Consumes: `RedisClientType` from `redis`.

- [ ] **Step 1: Define bounded OAuth records and the store interface**

Define records in `src/oauth/types.ts` for `RegisteredClient`, `AuthorizationTransaction`, `AuthorizationCodeRecord`, `AccessTokenRecord`, and `RefreshTokenRecord`. Define this store contract in `src/oauth/store.ts`:

```ts
export interface OAuthStore {
  registerClient(client: RegisteredClient): Promise<void>;
  getClient(clientId: string): Promise<RegisteredClient | null>;
  createTransaction(
    id: string,
    value: AuthorizationTransaction,
    ttlSeconds: number,
  ): Promise<void>;
  consumeTransaction(id: string): Promise<AuthorizationTransaction | null>;
  createAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void>;
  consumeAuthorizationCode(
    digest: string,
  ): Promise<AuthorizationCodeRecord | null>;
  createAccessToken(
    digest: string,
    value: AccessTokenRecord,
    ttlSeconds: number,
  ): Promise<void>;
  getAccessToken(digest: string): Promise<AccessTokenRecord | null>;
  rotateRefreshToken(
    input: RotateRefreshTokenInput,
  ): Promise<RotateRefreshTokenResult>;
  incrementRateLimit(key: string, ttlSeconds: number): Promise<number>;
  close(): Promise<void>;
}
```

- [ ] **Step 2: Write failing crypto tests**

Test SHA-256 determinism, 32-byte random tokens, S256 PKCE, signed CSRF tamper rejection, and both correct and incorrect passphrases:

```ts
expect(await verifyPkce(verifier, await pkceChallenge(verifier))).toBe(true);
expect(await verifyPkce(`${verifier}x`, await pkceChallenge(verifier))).toBe(
  false,
);
expect(await verifyPassphrase("correct horse", digest)).toBe(true);
expect(await verifyPassphrase("wrong horse", digest)).toBe(false);
```

- [ ] **Step 3: Run the crypto tests to verify failure**

```bash
npx vitest run tests/oauth-crypto.test.ts
```

Expected: FAIL because `src/oauth/crypto.ts` does not exist.

- [ ] **Step 4: Implement cryptographic helpers with Node crypto**

Use `randomBytes(32)`, `createHash('sha256')`, `createHmac('sha256')`, `timingSafeEqual`, and promisified `scrypt`. Parse only `scrypt$16384$8$1$<salt>$<digest>` and cap `maxmem` explicitly. Export:

```ts
export function randomToken(): string;
export function sha256Token(value: string): string;
export async function pkceChallenge(verifier: string): Promise<string>;
export async function verifyPkce(
  verifier: string,
  challenge: string,
): Promise<boolean>;
export async function verifyPassphrase(
  passphrase: string,
  encoded: string,
): Promise<boolean>;
export function signCsrf(value: string, key: string): string;
export function verifyCsrf(
  cookie: string,
  bodyValue: string,
  key: string,
): boolean;
```

- [ ] **Step 5: Write failing atomic-store tests against an in-memory contract harness**

The contract must prove `consumeTransaction` and `consumeAuthorizationCode` return a value once, access-token TTL is honored, rate-limit increments are atomic, and replay of a rotated refresh token returns `replayed` and revokes the token family.

- [ ] **Step 6: Implement Redis keys and Lua-backed atomic operations**

Use prefixes `client:`, `tx:`, `code:`, `access:`, `refresh:`, `refresh-used:`, and `family-revoked:`. Use `GETDEL` for transactions/codes. Implement refresh rotation in one Lua script that checks family revocation, marks the old digest used, writes the new digest, and assigns the thirty-day family TTL.

- [ ] **Step 7: Run the OAuth unit tests**

```bash
npx vitest run tests/oauth-crypto.test.ts tests/oauth-store.test.ts
```

Expected: PASS without a real Redis connection; Redis command shapes are tested with a strict fake client.

- [ ] **Step 8: Commit OAuth primitives**

```bash
git add src/oauth/types.ts src/oauth/crypto.ts src/oauth/store.ts src/oauth/redis-store.ts tests/oauth-crypto.test.ts tests/oauth-store.test.ts
git commit -m "feat: add durable OAuth primitives"
```

---

### Task 3: Discovery and dynamic client registration

**Files:**

- Create: `src/oauth/metadata.ts`
- Create: `src/oauth/registration.ts`
- Modify: `src/app.ts`
- Create: `tests/oauth-metadata.test.ts`
- Create: `tests/oauth-registration.test.ts`

**Interfaces:**

- Produces: `oauthMetadataRouter(config)` and `registrationRouter(config, store)`.
- Consumes: `OAuthStore.registerClient/getClient`, `AppConfig.publicOrigin`, and `AppConfig.resourceUrl`.

- [ ] **Step 1: Write failing discovery tests**

Assert exact values for:

```ts
expect(protectedResource.resource).toBe(
  "https://yahoo-mail-mcp.onrender.com/mcp",
);
expect(protectedResource.authorization_servers).toEqual([
  "https://yahoo-mail-mcp.onrender.com",
]);
expect(serverMetadata.code_challenge_methods_supported).toEqual(["S256"]);
expect(serverMetadata.grant_types_supported).toEqual([
  "authorization_code",
  "refresh_token",
]);
```

Test both `/.well-known/oauth-protected-resource` and `/.well-known/oauth-protected-resource/mcp`.

- [ ] **Step 2: Implement discovery documents**

Return protected-resource and authorization-server metadata with exact HTTPS endpoints: `/authorize`, `/token`, and `/register`. Advertise bearer header usage, S256, `none` token endpoint auth for public clients, and the two supported grants.

- [ ] **Step 3: Write failing dynamic-registration tests**

Accept a bounded public client with `token_endpoint_auth_method: 'none'`. Reject missing redirect URIs, wildcard URIs, fragments, credentials, non-loopback HTTP, more than ten redirect URIs, and bodies over 32 KiB. Prove the generated `client_id` is random and the stored redirect list matches exactly.

- [ ] **Step 4: Implement `/register`**

Use `express.json({ limit: '32kb', type: 'application/json' })`, Zod validation, registration rate limiting through `OAuthStore.incrementRateLimit`, and `Cache-Control: no-store`. Store only bounded public-client metadata; do not issue a client secret.

- [ ] **Step 5: Run metadata and registration tests**

```bash
npx vitest run tests/oauth-metadata.test.ts tests/oauth-registration.test.ts
```

Expected: PASS.

- [ ] **Step 6: Commit discovery and registration**

```bash
git add src/oauth/metadata.ts src/oauth/registration.ts src/app.ts tests/oauth-metadata.test.ts tests/oauth-registration.test.ts
git commit -m "feat: add OAuth discovery and registration"
```

---

### Task 4: Single-user authorization and passphrase verification

**Files:**

- Create: `src/oauth/authorization.ts`
- Create: `tests/oauth-authorization.test.ts`
- Modify: `src/app.ts`

**Interfaces:**

- Produces: `authorizationRouter(config, store)` for `GET /authorize` and `POST /authorize`.
- Consumes: registered client metadata, signed CSRF helpers, passphrase verifier, transaction/code store methods.

- [ ] **Step 1: Write failing authorization-request tests**

Cover required `response_type=code`, known `client_id`, exact registered `redirect_uri`, `resource === config.resourceUrl`, non-empty `state`, S256 challenge syntax, and bounded scope. Invalid redirect URIs must never receive redirects.

- [ ] **Step 2: Write failing login-form security tests**

Assert `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'`, `Cache-Control: no-store`, an HTTP-only secure SameSite=Lax CSRF cookie, HTML escaping, 16 KiB form limit, and no Yahoo email or infrastructure value in the response.

- [ ] **Step 3: Implement GET `/authorize`**

Validate the request, create a ten-minute `AuthorizationTransaction`, set a signed CSRF cookie, and render only the service label, passphrase field, hidden transaction ID, hidden CSRF value, Allow, and Deny controls.

- [ ] **Step 4: Write failing POST authorization tests**

Test CSRF mismatch, expired/consumed transaction, incorrect passphrase, rate limit after five failures per transaction/IP in fifteen minutes, explicit denial, and successful redirect containing only `code` and the original `state`.

- [ ] **Step 5: Implement POST `/authorize`**

Use `express.urlencoded({ extended: false, limit: '16kb' })`. Consume the transaction atomically, verify CSRF and passphrase, write a SHA-256-indexed five-minute authorization code bound to client, redirect URI, resource, challenge, and scope, then redirect to the exact registered URI.

- [ ] **Step 6: Run authorization tests**

```bash
npx vitest run tests/oauth-authorization.test.ts
```

Expected: PASS.

- [ ] **Step 7: Commit single-user authorization**

```bash
git add src/oauth/authorization.ts src/app.ts tests/oauth-authorization.test.ts
git commit -m "feat: add single-user OAuth authorization"
```

---

### Task 5: Token exchange, rotation, and resource authorization

**Files:**

- Create: `src/oauth/token.ts`
- Create: `src/oauth/middleware.ts`
- Create: `tests/oauth-token.test.ts`
- Create: `tests/oauth-middleware.test.ts`
- Modify: `src/app.ts`
- Delete: `src/security/auth.ts`

**Interfaces:**

- Produces: `tokenRouter(config, store)` and `requireMcpBearer(config, store)`.
- Consumes: atomic authorization-code and refresh-token store operations.

- [ ] **Step 1: Write failing authorization-code token tests**

Test URL-encoded form enforcement, required `grant_type`, client ID, exact redirect URI, exact resource, valid verifier syntax, S256 match, single consumption, and `Cache-Control: no-store`. A successful exchange returns:

```ts
expect(response.body).toMatchObject({
  token_type: "Bearer",
  expires_in: 900,
  scope: "mcp:read",
});
expect(response.body.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
expect(response.body.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
```

- [ ] **Step 2: Implement authorization-code exchange**

Consume the code before validating reusable inputs, verify every binding and S256 PKCE, create SHA-256-indexed opaque access/refresh records, and return raw tokens only in the successful TLS response.

- [ ] **Step 3: Write failing refresh-token tests**

Prove every refresh rotates both access and refresh tokens, the old refresh token cannot succeed, replay revokes the family, and a revoked family rejects the newest refresh token.

- [ ] **Step 4: Implement refresh rotation**

Call `OAuthStore.rotateRefreshToken` with the old digest, new digest, family ID, client ID, resource, scope, and TTLs. Return `invalid_grant` for missing, expired, replayed, or revoked tokens without distinguishing them publicly.

- [ ] **Step 5: Write failing bearer-middleware tests**

Test missing/malformed/wrong/expired/wrong-resource tokens, query-string token rejection, success context, and the exact challenge:

```ts
expect(response.headers["www-authenticate"]).toContain(
  'resource_metadata="https://yahoo-mail-mcp.onrender.com/.well-known/oauth-protected-resource/mcp"',
);
```

- [ ] **Step 6: Implement and wire bearer authorization**

Hash the header token, load its access record, validate expiry and exact resource, attach only `{ clientId, scope }` to `res.locals.auth`, and protect every `/mcp` method before invoking the MCP handler. Remove `bearerAuth` and `MCP_API_TOKEN` completely.

- [ ] **Step 7: Run token and middleware tests**

```bash
npx vitest run tests/oauth-token.test.ts tests/oauth-middleware.test.ts tests/app.test.ts
```

Expected: PASS.

- [ ] **Step 8: Commit token and resource authorization**

```bash
git add src/oauth/token.ts src/oauth/middleware.ts src/app.ts tests/oauth-token.test.ts tests/oauth-middleware.test.ts tests/app.test.ts
git rm src/security/auth.ts
git commit -m "feat: protect MCP with portable OAuth"
```

---

### Task 6: Secret-safe operations, passphrase hashing, and Render Blueprint

**Files:**

- Create: `scripts/hash-passphrase.mjs`
- Create: `tests/hash-passphrase.test.ts`
- Create: `render.yaml`
- Modify: `.env.example`
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `package.json`

**Interfaces:**

- Produces: `npm run hash-passphrase`, which reads from a TTY without echo and prints only the salted scrypt digest.
- Produces: a Render Blueprint containing one web service and one Key Value service.

- [ ] **Step 1: Write a failing deterministic hash-format test**

Extract a pure exported helper from the script and assert:

```ts
expect(await encodePassphrase("private phrase", fixedSalt)).toMatch(
  /^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/,
);
```

- [ ] **Step 2: Implement the hidden-input hashing script**

Use TTY raw mode, mask input, restore terminal state in `finally`, reject input shorter than sixteen characters, generate a sixteen-byte salt, derive a 32-byte scrypt digest, and print only the encoded digest. Add:

```json
"hash-passphrase": "node scripts/hash-passphrase.mjs"
```

- [ ] **Step 3: Add the Render Blueprint**

Create `render.yaml` with a Node web service using `npm ci && npm run build`, `npm start`, `/health`, `HOST=0.0.0.0`, Render's automatic `RENDER_EXTERNAL_URL`, and `REDIS_URL` from the Key Value connection string. Mark `YAHOO_EMAIL`, `YAHOO_APP_PASSWORD`, `MCP_LOGIN_PASSPHRASE_SCRYPT`, `OAUTH_COOKIE_KEY`, and `ALLOWED_HOSTS` as dashboard-supplied secrets/values. Configure Key Value with `noeviction` so OAuth state is never silently evicted under pressure.

- [ ] **Step 4: Replace Cloudflare/static-token documentation**

Document Render setup, required secrets, hidden passphrase hashing, OAuth endpoints, one-mailbox scope, safe smoke order, rollback, and secret rotation. `.env.example` contains names and safe defaults only; `.gitignore` continues to exclude `.env` and local worktrees.

- [ ] **Step 5: Run all repository verification**

```bash
npm run format
npm run lint
npm run typecheck
npm test
npm run build
```

Expected: all checks pass and no test contacts Yahoo or Render.

- [ ] **Step 6: Scan the bundle and Git diff for secret patterns**

```bash
rg -n "MCP_API_TOKEN|app-password-value|private phrase" src scripts render.yaml README.md SECURITY.md .env.example
git diff --check
git status --short
```

Expected: `MCP_API_TOKEN` is absent; test-only literals do not appear in runtime or deployment files; diff check is clean.

- [ ] **Step 7: Commit deployment configuration and documentation**

```bash
git add scripts/hash-passphrase.mjs tests/hash-passphrase.test.ts render.yaml .env.example .gitignore README.md SECURITY.md package.json package-lock.json
git commit -m "infra: prepare secure Render deployment"
```

---

### Task 7: End-to-end protocol verification and deployment gate

**Files:**

- Create: `tests/oauth-flow.test.ts`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`

**Interfaces:**

- Consumes: the complete Express app with an in-memory `OAuthStore` contract implementation.
- Produces: proof that MCP Inspector-compatible OAuth reaches the five tools without Yahoo data in test output.

- [ ] **Step 1: Write the end-to-end OAuth test**

Drive registration, authorization GET, CSRF cookie extraction, authorization POST, PKCE token exchange, authenticated MCP initialization, `tools/list`, refresh rotation, and rejection of the old access/refresh credentials. Stub `createMcpServer` with the same five tool names and no mailbox data.

- [ ] **Step 2: Add log-capture assertions**

Capture `console.error` and assert logs omit passphrase, code, verifier, access token, refresh token, Yahoo email, sender, subject, body, and folder names across both successful and failed flows.

- [ ] **Step 3: Run the complete verification gate**

```bash
npm run format
npm run lint
npm run typecheck
npm test
npm run build
```

Expected: all checks pass; CI stays network-independent and secret-free.

- [ ] **Step 4: Update CI to use `npm ci` and the aggregate verification command**

Add `"verify": "npm run format && npm run lint && npm run typecheck && npm test && npm run build"` and make CI run `npm ci` followed by `npm run verify` on Node 20.

- [ ] **Step 5: Commit the final verification gate**

```bash
git add tests/oauth-flow.test.ts .github/workflows/ci.yml README.md package.json package-lock.json
git commit -m "test: verify complete Render OAuth flow"
```

- [ ] **Step 6: Stop for production-resource approval**

Present the verified commit, Render web-service plan, Key Value plan, region, and any monthly charge. Obtain explicit approval before creating Render resources or selecting a paid plan.

- [ ] **Step 7: After approval, push the reviewed branch and create the Blueprint resources**

Push the implementation branch, validate `render.yaml`, create the Render Blueprint in `My Workspace`, and leave all secret-backed fields unset so deployment fails closed.

- [ ] **Step 8: Collect secrets through hidden/local controls**

Generate `MCP_LOGIN_PASSPHRASE_SCRYPT` through `npm run hash-passphrase`, generate `OAUTH_COOKIE_KEY` with 32 random bytes, and enter them with the Yahoo email/app password in Render without printing any value. Do not put secrets in chat, shell history, files, Git, logs, or deployment output.

- [ ] **Step 9: Verify the live service in minimum-exposure order**

Verify `/health` returns `200 {"status":"ok"}`, unauthenticated `/mcp` returns `401`, discovery documents return exact HTTPS metadata, MCP Inspector completes registration/PKCE/passphrase authorization, and `tools/list` reports exactly five tools. Then run `list_folders` and one bounded `get_morning_brief_emails` call while reporting only pass/fail and retaining no mailbox output.

- [ ] **Step 10: Record rollback and completion evidence**

Record the deployed Git commit, Render service ID, deploy ID, public MCP URL, health status, OAuth handshake result, five-tool result, and sanitized Yahoo smoke result. Do not record any secret or mailbox value.
