# Cloudflare Worker Deployment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert the security-first Yahoo Mail MCP server into an OAuth-protected native Cloudflare Worker that lets one authorized ChatGPT user retrieve bounded, sanitized, read-only mail.

**Architecture:** A stateless `createMcpHandler()` Worker serves Streamable HTTP at `/mcp`. `@cloudflare/workers-oauth-provider` fronts the handler and delegates user authentication to a Cloudflare Access for SaaS OIDC application, with durable grant/state storage in `OAUTH_KV`. Yahoo access remains isolated behind a `MailReader` interface and uses verified TLS to IMAP port 993.

**Tech Stack:** TypeScript, Cloudflare Workers, Wrangler 4.127.1, Agents 0.22.0, MCP Server SDK 2.0.0, Workers OAuth Provider 0.10.3, Workers Vitest Pool 0.22.0, Zod 4, ImapFlow, Vitest.

**Spec:** `docs/superpowers/specs/2026-08-30-cloudflare-worker-deployment-design.md`

## Global Constraints

- Expose only `POST /mcp` using stateless Streamable HTTP and `GET /health` returning exactly `{ "status": "ok" }`.
- Expose only `get_morning_brief_emails`, `list_emails`, `search_emails`, `read_email`, and `list_folders`.
- Yahoo mailboxes must always open read-only over `imap.mail.yahoo.com:993` with certificate and hostname verification.
- Sanitize and truncate all email-derived text before MCP output construction.
- Never log mailbox content, email addresses, subjects, tool arguments, OTPs, URLs, credentials, OAuth codes, or tokens.
- Missing Worker bindings, invalid OAuth state, KV errors, rate-limiter errors, and authentication failures must fail closed.
- Store OAuth state in `OAUTH_KV`; never add a production in-memory token store.
- Store Yahoo and Access credentials only as Worker secrets; never write them to Git, CI, `.dev.vars`, tests, or documentation.
- Keep `.env` and `.env.*` ignored; `.env.example` remains the only exception.
- Do not fall back to deprecated `McpAgent` if stateless OAuth wiring fails. Stop and report the upstream incompatibility.

---

## Planned File Structure

- `src/index.ts` — Worker export and OAuth provider composition only.
- `src/worker.ts` — health route, MCP request guards, rate limiting, and stateless MCP adapter.
- `src/config.ts` — Worker binding validation and non-secret limits.
- `src/mcp.ts` — five read-only tools, built against the `MailReader` interface.
- `src/yahoo.ts` — Worker-compatible read-only Yahoo IMAP adapter.
- `src/auth/access-handler.ts` — `/authorize` and `/callback` flow against Access OIDC.
- `src/auth/oauth-state.ts` — CSRF, PKCE, signed one-time state, and approved-client cookie helpers.
- `src/auth/oidc.ts` — Access discovery URL validation, code exchange, and ID-token verification.
- `src/types.ts` — `WorkerEnv`, `AuthProps`, `MailReader`, and rate-limit interfaces.
- `tests/config.test.ts` — fail-closed Worker binding tests.
- `tests/mcp.test.ts` — exact tool registry, input bounds, and sanitizer-before-output tests.
- `tests/worker.test.ts` — health, routing, size, method, auth-context, and rate-limit tests.
- `tests/auth.test.ts` — CSRF, PKCE, OAuth state, OIDC claim, and identity-policy tests.
- `tests/yahoo.test.ts` — read-only mailbox and TLS option tests with an injected fake IMAP client.
- `tests/secret-leak.test.ts` — repository/runtime response and log leakage assertions.
- `wrangler.jsonc` — Worker entry point, compatibility date, bindings, observability, and CPU limit.
- `worker-configuration.d.ts` — generated Worker binding types.
- `vitest.config.ts` — Cloudflare Workers test-pool configuration.
- `.github/workflows/ci.yml` — deterministic install and Worker gates.
- `README.md`, `SECURITY.md` — Cloudflare deployment, ChatGPT connection, rollback, and incident procedure.

### Task 1: Lock Dependencies and Prove Stateless OAuth Adapter Wiring

**Files:**

- Modify: `package.json`
- Create: `package-lock.json`
- Create: `src/types.ts`
- Create: `src/auth/stateless-adapter.ts`
- Create: `tests/stateless-adapter.test.ts`
- Modify: `tsconfig.json`
- Modify: `.gitignore`

**Interfaces:**

- Produces: `WorkerEnv`, `AuthProps`, and `createStatelessApiHandler(createServer)`.
- `createStatelessApiHandler` returns `{ fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> }` for `OAuthProvider.apiHandler`.

- [ ] **Step 1: Verify the local secret file is ignored without editing a redundant rule**

Run:

```powershell
git check-ignore -v .env
git ls-files --error-unmatch .env
```

Expected: the first command cites `.gitignore`; the second exits non-zero. Preserve the existing rules:

```gitignore
.env
.env.*
!.env.example
```

- [ ] **Step 2: Install and pin the Worker toolchain**

Run:

```powershell
npm install agents@0.22.0 @cloudflare/workers-oauth-provider@0.10.3
npm install --save-dev wrangler@4.127.1 @cloudflare/vitest-pool-workers@0.22.0
npm uninstall express @modelcontextprotocol/express @modelcontextprotocol/node express-rate-limit helmet dotenv
```

Update scripts to this exact shape while retaining lint/format/test commands:

```json
{
  "scripts": {
    "dev": "wrangler dev",
    "deploy": "wrangler deploy",
    "build": "wrangler deploy --dry-run --outdir dist/worker",
    "typecheck": "tsc -p tsconfig.json --noEmit",
    "cf-typegen": "wrangler types",
    "test": "vitest run",
    "verify": "npm run format && npm run lint && npm run typecheck && npm test && npm run build"
  }
}
```

- [ ] **Step 3: Write the failing stateless adapter test**

```ts
import { describe, expect, it, vi } from "vitest";
import { createStatelessApiHandler } from "../src/auth/stateless-adapter.js";

describe("stateless OAuth API adapter", () => {
  it("passes an authenticated request to a fresh MCP handler", async () => {
    const handler = createStatelessApiHandler(
      () => ({ close: vi.fn() }) as never,
    );
    expect(handler).toHaveProperty("fetch");
    expect(typeof handler.fetch).toBe("function");
  });
});
```

- [ ] **Step 4: Run the test and confirm the module is missing**

Run: `npx vitest run tests/stateless-adapter.test.ts`

Expected: FAIL because `src/auth/stateless-adapter.ts` does not exist.

- [ ] **Step 5: Implement the supported adapter shape and compile it against current package types**

```ts
import { createMcpHandler } from "agents/mcp/server";
import type { McpServer } from "@modelcontextprotocol/server";
import type { WorkerEnv } from "../types.js";

export function createStatelessApiHandler(
  createServer: (env: WorkerEnv) => McpServer,
) {
  return {
    async fetch(
      request: Request,
      env: WorkerEnv,
      ctx: ExecutionContext,
    ): Promise<Response> {
      const handler = createMcpHandler(() => createServer(env), {
        route: "/mcp",
        legacy: "stateless",
        responseMode: "auto",
      });
      return handler(request, env, ctx);
    },
  };
}
```

Define only non-secret types in `src/types.ts`:

```ts
export interface AuthProps {
  email: string;
  name: string;
  subject: string;
}

export interface WorkerEnv {
  YAHOO_EMAIL: string;
  YAHOO_APP_PASSWORD: string;
  ACCESS_CLIENT_ID: string;
  ACCESS_CLIENT_SECRET: string;
  ACCESS_TOKEN_URL: string;
  ACCESS_AUTHORIZATION_URL: string;
  ACCESS_JWKS_URL: string;
  COOKIE_ENCRYPTION_KEY: string;
  OAUTH_KV: KVNamespace;
  MCP_RATE_LIMITER: RateLimit;
}
```

If `OAuthProvider` rejects this `apiHandler` shape or authenticated SDK `AuthInfo` is absent in an integration test, stop. Do not substitute `McpAgent`.

Add a compile-time provider fixture to the test so the proof covers the actual provider contract:

```ts
const apiHandler = createStatelessApiHandler(() => fakeServer());
const provider = new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  defaultHandler: {
    fetch: async () => new Response("not configured", { status: 503 }),
  },
});
expect(provider).toHaveProperty("fetch");
```

- [ ] **Step 6: Run focused and type tests**

Run:

```powershell
npx vitest run tests/stateless-adapter.test.ts
npm run typecheck
```

Expected: PASS with no deprecated MCP imports.

- [ ] **Step 7: Commit the toolchain proof**

```powershell
git add package.json package-lock.json tsconfig.json src/types.ts src/auth/stateless-adapter.ts tests/stateless-adapter.test.ts
git commit -m "build: add Cloudflare Worker toolchain"
```

### Task 2: Convert Configuration and MCP Tools to Worker-Native Dependency Injection

**Files:**

- Modify: `src/config.ts`
- Modify: `src/mcp.ts`
- Modify: `src/types.ts`
- Delete: `src/security/auth.ts`
- Replace: `tests/config-auth.test.ts` with `tests/config.test.ts`
- Create: `tests/mcp.test.ts`

**Interfaces:**

- Produces: `loadWorkerConfig(env: WorkerEnv): AppConfig`.
- Produces: `MailReader` with `listFolders()`, `listEmails(options)`, and `readEmail(uid, folder)`.
- Produces: `createYahooMcpServer(config: AppConfig, reader: MailReader): McpServer`.

- [ ] **Step 1: Write failing configuration tests**

```ts
import { describe, expect, it } from "vitest";
import { loadWorkerConfig } from "../src/config.js";

describe("Worker configuration", () => {
  it("fails closed without Yahoo secrets", () => {
    expect(() => loadWorkerConfig({} as never)).toThrow(
      /YAHOO_EMAIL, YAHOO_APP_PASSWORD/,
    );
  });

  it("does not include the deployment token in application configuration", () => {
    const config = loadWorkerConfig(validWorkerEnv());
    expect(config).not.toHaveProperty("cloudflareApiToken");
  });
});
```

- [ ] **Step 2: Run the configuration test and confirm failure**

Run: `npx vitest run tests/config.test.ts`

Expected: FAIL because `loadWorkerConfig` is not exported.

- [ ] **Step 3: Replace process environment parsing with explicit Worker binding validation**

```ts
const secretSchema = z.object({
  YAHOO_EMAIL: z.string().email(),
  YAHOO_APP_PASSWORD: z.string().min(8),
});

export function loadWorkerConfig(env: WorkerEnv) {
  const result = secretSchema.safeParse(env);
  if (!result.success) {
    const names = result.error.issues
      .map((issue) => issue.path.join("."))
      .join(", ");
    throw new Error(`Invalid or missing required configuration: ${names}`);
  }
  return {
    yahooEmail: result.data.YAHOO_EMAIL,
    yahooAppPassword: result.data.YAHOO_APP_PASSWORD,
    maxEmailsPerRequest: 25,
    maxPreviewChars: 600,
    maxReadChars: 5000,
    imapConnectTimeoutMs: 15000,
    imapCommandTimeoutMs: 20000,
  } as const;
}
```

Remove `PORT`, `HOST`, `ALLOWED_HOSTS`, `ALLOWED_ORIGINS`, and `MCP_API_TOKEN`; the Worker and OAuth provider own those concerns.

- [ ] **Step 4: Write failing MCP dependency-injection tests**

```ts
it("registers exactly five read-only tools", async () => {
  const reader = fakeMailReader();
  const server = createYahooMcpServer(validConfig(), reader);
  const tools = await listRegisteredTools(server);
  expect(tools.map((tool) => tool.name).sort()).toEqual([
    "get_morning_brief_emails",
    "list_emails",
    "list_folders",
    "read_email",
    "search_emails",
  ]);
});
```

- [ ] **Step 5: Add the `MailReader` interface and inject it into the server factory**

```ts
export interface MailReader {
  listFolders(): Promise<string[]>;
  listEmails(options: ListEmailOptions): Promise<SafeMailSummary[]>;
  readEmail(uid: number, folder?: string): Promise<SafeMailDetail | null>;
}

export interface ListEmailOptions {
  folder?: string;
  limit?: number;
  unreadOnly?: boolean;
  since?: Date;
  query?: string;
}

export interface SafeMailSummary {
  uid: number;
  folder: string;
  senderName: string;
  senderEmail: string;
  subject: string;
  receivedAt: string | null;
  unread: boolean;
  hasAttachments: boolean;
  preview: string;
}

export interface SafeMailDetail extends SafeMailSummary {
  body: string;
}

export function createYahooMcpServer(
  config: AppConfig,
  reader: MailReader,
): McpServer {
  const server = new McpServer({
    name: "yahoo-mail-chatgpt-mcp",
    version: "0.2.0",
  });
  // Register the existing five tools against reader; register no write tools.
  return server;
}
```

- [ ] **Step 6: Run focused tests**

Run: `npx vitest run tests/config.test.ts tests/mcp.test.ts`

Expected: PASS; malformed limits fail Zod validation and no write tool is listed.

- [ ] **Step 7: Commit Worker-native configuration and tools**

```powershell
git add src/config.ts src/mcp.ts src/types.ts tests/config.test.ts tests/mcp.test.ts
git rm src/security/auth.ts tests/config-auth.test.ts
git commit -m "refactor: make MCP tools Worker native"
```

### Task 3: Add Worker Routing, Request Guards, and Rate Limiting

**Files:**

- Create: `src/worker.ts`
- Modify: `src/index.ts`
- Modify: `src/auth/stateless-adapter.ts`
- Create: `tests/worker.test.ts`
- Create: `wrangler.jsonc`
- Create: `vitest.config.ts`
- Create: `worker-configuration.d.ts`

**Interfaces:**

- Produces: `createMcpApiHandler(): ExportedHandler<WorkerEnv>`.
- Produces: `securityHeaders(response: Response): Response`.
- Consumes: `loadWorkerConfig`, `createYahooMcpServer`, and `MCP_RATE_LIMITER.limit({ key })`.

- [ ] **Step 1: Write failing route and guard tests**

```ts
it("returns a minimal health response", async () => {
  const response = await SELF.fetch("https://example.com/health");
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ status: "ok" });
});

it("rejects oversized MCP requests before protocol parsing", async () => {
  const response = await SELF.fetch("https://example.com/mcp", {
    method: "POST",
    headers: { "content-length": String(256 * 1024 + 1) },
  });
  expect(response.status).toBe(413);
});
```

- [ ] **Step 2: Run the Worker tests and confirm failure**

Run: `npx vitest run tests/worker.test.ts`

Expected: FAIL because the Worker entry does not exist.

- [ ] **Step 3: Implement exact health and MCP guards**

```ts
const MAX_MCP_BODY_BYTES = 256 * 1024;

export async function guardMcpRequest(
  request: Request,
  env: WorkerEnv,
): Promise<Response | null> {
  if (request.method !== "POST") {
    return Response.json(
      { error: "method_not_allowed" },
      { status: 405, headers: { Allow: "POST" } },
    );
  }
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > MAX_MCP_BODY_BYTES) {
    return Response.json({ error: "request_too_large" }, { status: 413 });
  }
  const authorization = request.headers.get("authorization") ?? "";
  const keyBytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(authorization),
  );
  const key = Array.from(new Uint8Array(keyBytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
  const outcome = await env.MCP_RATE_LIMITER.limit({ key });
  return outcome.success
    ? null
    : Response.json({ error: "rate_limited" }, { status: 429 });
}
```

Catch missing/rate-limiter binding errors and return `503 { "error": "service_unavailable" }`; do not proceed to MCP.

- [ ] **Step 4: Configure the local Worker without remote resource IDs**

Create `wrangler.jsonc` with the production entry and rate-limit binding; add the `OAUTH_KV` remote ID only after Task 7 creates it:

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "yahoo-mail-chatgpt-mcp",
  "main": "src/index.ts",
  "compatibility_date": "2026-08-30",
  "limits": { "cpu_ms": 30000 },
  "observability": { "enabled": true, "head_sampling_rate": 1 },
  "ratelimits": [
    {
      "name": "MCP_RATE_LIMITER",
      "namespace_id": "1001",
      "simple": { "limit": 60, "period": 60 },
    },
  ],
}
```

The numeric rate-limit namespace is an application-local identifier, not a secret or Cloudflare resource ID.

Until Task 4 composes the OAuth provider, replace the removed Express entry point with a fail-closed default export so no intermediate commit can expose MCP publicly:

```ts
export default {
  async fetch(): Promise<Response> {
    return Response.json({ error: "oauth_not_configured" }, { status: 503 });
  },
} satisfies ExportedHandler;
```

- [ ] **Step 5: Run Worker tests and dry bundle**

Run:

```powershell
npx vitest run tests/worker.test.ts
npm run typecheck
npm run build
```

Expected: PASS; the bundle contains no Express listener and no SSE route.

- [ ] **Step 6: Commit Worker routing**

```powershell
git add src/index.ts src/worker.ts src/auth/stateless-adapter.ts tests/worker.test.ts wrangler.jsonc vitest.config.ts worker-configuration.d.ts
git commit -m "feat: add guarded Cloudflare Worker MCP route"
```

### Task 4: Implement Cloudflare Access OAuth with Durable State

**Files:**

- Create: `src/auth/access-handler.ts`
- Create: `src/auth/oauth-state.ts`
- Create: `src/auth/oidc.ts`
- Modify: `src/index.ts`
- Create: `tests/auth.test.ts`
- Modify: `tests/worker.test.ts`

**Interfaces:**

- Produces: `handleAccessRequest(request, env, ctx): Promise<Response>`.
- Produces: `createOAuthState`, `consumeOAuthState`, `generatePkce`, `validateCsrf`, and `verifyAccessIdToken`.
- `AuthProps` contains only `email`, `name`, and `subject`; it never contains an upstream access token.

- [ ] **Step 1: Write failing OAuth security tests**

```ts
it("consumes signed OAuth state once", async () => {
  const state = await createOAuthState(
    authRequest,
    env.OAUTH_KV,
    env.COOKIE_ENCRYPTION_KEY,
  );
  await expect(
    consumeOAuthState(state.token, env.OAUTH_KV, env.COOKIE_ENCRYPTION_KEY),
  ).resolves.toMatchObject({
    request: authRequest,
  });
  await expect(
    consumeOAuthState(state.token, env.OAUTH_KV, env.COOKIE_ENCRYPTION_KEY),
  ).rejects.toThrow(/invalid or expired state/i);
});

it("rejects a validly signed ID token with the wrong audience", async () => {
  await expect(
    verifyAccessIdToken(tokenWithWrongAudience, env),
  ).rejects.toThrow(/invalid token/);
});
```

Cover CSRF mismatch, unsigned state, expired state, wrong issuer, wrong audience, expired ID token, missing email, disallowed redirect scheme, and upstream error sanitization.

- [ ] **Step 2: Run tests and confirm missing modules**

Run: `npx vitest run tests/auth.test.ts`

Expected: FAIL because the OAuth modules do not exist.

- [ ] **Step 3: Implement one-time HMAC-signed state and PKCE**

```ts
export interface StoredOAuthState {
  request: AuthRequest;
  verifier: string;
  nonce: string;
}

export async function createOAuthState(
  request: AuthRequest,
  kv: KVNamespace,
  secret: string,
): Promise<{ token: string; challenge: string; nonce: string }> {
  const id = crypto.randomUUID();
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const nonce = crypto.randomUUID();
  const signature = await hmac(id, secret);
  await kv.put(
    `oauth:state:${id}`,
    JSON.stringify({ request, verifier, nonce }),
    { expirationTtl: 600 },
  );
  return {
    token: `${id}.${signature}`,
    challenge: await sha256Base64Url(verifier),
    nonce,
  };
}
```

`consumeOAuthState` must verify HMAC before KV lookup, delete the KV key before returning, and never log the token or stored request.

- [ ] **Step 4: Implement Access OIDC exchange and claim validation**

`verifyAccessIdToken(token, env, expectedNonce)` must verify:

```ts
const requiredClaims = z.object({
  iss: z.string().url(),
  aud: z.union([z.string(), z.array(z.string())]),
  sub: z.string().min(1),
  email: z.string().email(),
  name: z.string().default("Yahoo Mail user"),
  exp: z.number().int(),
  iat: z.number().int(),
  nonce: z.string().min(1),
});
```

The issuer must equal the origin derived from `ACCESS_AUTHORIZATION_URL`, audience must contain `ACCESS_CLIENT_ID`, `exp` must be in the future, `iat` must not be unreasonably future-dated, and `nonce` must equal the stored value.

- [ ] **Step 5: Implement authorization and callback routes**

```ts
const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
  request: oauthRequest,
  userId: claims.sub,
  scope: oauthRequest.scope,
  props: {
    email: claims.email,
    name: claims.name,
    subject: claims.sub,
  } satisfies AuthProps,
  metadata: { label: "Yahoo Mail read-only" },
});
```

The approval page must HTML-escape client metadata, allow only `https:` client metadata URLs in production, use `__Host-` cookies with `HttpOnly; Secure; SameSite=Lax`, and validate a one-use CSRF token before redirecting to Access.

- [ ] **Step 6: Compose the provider in `src/index.ts`**

```ts
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { createMcpApiHandler } from "./worker.js";
import { handleAccessRequest } from "./auth/access-handler.js";

export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: createMcpApiHandler(),
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  defaultHandler: { fetch: handleAccessRequest },
});
```

- [ ] **Step 7: Run OAuth and routing tests**

Run:

```powershell
npx vitest run tests/auth.test.ts tests/worker.test.ts
npm run typecheck
```

Expected: PASS; unauthenticated `/mcp` returns OAuth-compatible `401`, and `/health` remains content-minimal.

- [ ] **Step 8: Commit OAuth**

```powershell
git add src/index.ts src/auth/access-handler.ts src/auth/oauth-state.ts src/auth/oidc.ts tests/auth.test.ts tests/worker.test.ts
git commit -m "feat: protect MCP with Cloudflare Access OAuth"
```

### Task 5: Prove Yahoo IMAP Compatibility and Expand Sanitization

**Files:**

- Modify: `src/yahoo.ts`
- Modify: `src/security/redact.ts`
- Create: `tests/yahoo.test.ts`
- Modify: `tests/redact.test.ts`
- Create: `tests/secret-leak.test.ts`

**Interfaces:**

- `YahooMailReader` implements `MailReader`.
- Produces: `createImapClient(config, factory?)` so TLS and read-only options are testable without Yahoo credentials.

- [ ] **Step 1: Write failing Yahoo security tests**

```ts
it("opens every mailbox read-only with verified TLS", async () => {
  const fake = fakeImapClient();
  const reader = new YahooMailReader(validConfig(), () => fake);
  await reader.listEmails({ folder: "INBOX", limit: 1 });
  expect(fake.mailboxOpen).toHaveBeenCalledWith("INBOX", { readOnly: true });
  expect(fake.options.tls).toMatchObject({
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
  });
});
```

Also assert logout/close on success, timeout, parse failure, and search failure; assert result counts never exceed 25.

- [ ] **Step 2: Add sanitizer bypass tests before modifying sanitization**

```ts
expect(sanitizeEmailText("Verification c.o.d.e: 6 5 4 3 2 1")).not.toContain(
  "6 5 4 3 2 1",
);
expect(
  sanitizeEmailText("https://example.com/%70assword/reset?%74oken=secret"),
).toBe("[REDACTED LINK]");
expect(sanitizeEmailText("<p>OTP&nbsp;12&#45;34&#45;56</p>")).not.toContain(
  "12-34-56",
);
```

- [ ] **Step 3: Run focused tests and confirm the new bypass cases fail**

Run: `npx vitest run tests/yahoo.test.ts tests/redact.test.ts`

Expected: at least the encoded URL/entity cases fail before implementation.

- [ ] **Step 4: Make parsing and redaction Worker-safe**

Decode numeric and named HTML entities before code matching, percent-decode URL paths/parameter names for classification, remove control characters, and suppress the whole message if sanitization throws. Do not fetch remote HTML resources or attachment bodies.

- [ ] **Step 5: Prove ImapFlow bundles for Workers**

Run:

```powershell
npm run build
rg -n "node:http|createServer|listen\(|SSEServerTransport" dist/worker
```

Expected: Wrangler dry-run PASS and no forbidden server/listener/SSE code. If ImapFlow imports an unsupported runtime API, replace only `src/yahoo.ts` with a `cloudflare:sockets`/`node:tls` adapter and rerun the same contract tests. Do not weaken TLS or read-only assertions.

- [ ] **Step 6: Add secret-leak tests**

```ts
it("does not expose sentinel secrets in errors, logs, health, or MCP output", async () => {
  const sentinels = [
    "YAHOO_SECRET_SENTINEL",
    "OAUTH_SECRET_SENTINEL",
    "OTP_492811",
  ];
  const observed = await exerciseFailurePaths(sentinels);
  for (const secret of sentinels) expect(observed).not.toContain(secret);
});
```

- [ ] **Step 7: Run security tests and commit**

Run: `npx vitest run tests/yahoo.test.ts tests/redact.test.ts tests/secret-leak.test.ts`

```powershell
git add src/yahoo.ts src/security/redact.ts tests/yahoo.test.ts tests/redact.test.ts tests/secret-leak.test.ts
git commit -m "test: harden Yahoo Worker data handling"
```

### Task 6: Make CI Deterministic and Document Worker Operations

**Files:**

- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `SECURITY.md`
- Modify: `.env.example`
- Delete: `Dockerfile`

**Interfaces:**

- CI produces no deployment and requires no real credentials.
- README documents exact secret names and safe interactive commands, never example secret values resembling real credentials.

- [ ] **Step 1: Replace nondeterministic install and add Worker gates**

```yaml
- run: npm ci
- run: npm run format
- run: npm run lint
- run: npm run typecheck
- run: npm test
- run: npm run build
```

Keep workflow permissions at `contents: read`; do not add Cloudflare or Yahoo secrets to GitHub Actions.

- [ ] **Step 2: Update local configuration documentation**

`.env.example` must contain placeholders only and explicitly state that production uses `wrangler secret put`. Keep deployment-only `CLOUDFLARE_API_TOKEN` out of `.env.example`.

- [ ] **Step 3: Replace container deployment documentation**

Document these exact production secret commands:

```powershell
npx wrangler secret put YAHOO_EMAIL
npx wrangler secret put YAHOO_APP_PASSWORD
npx wrangler secret put ACCESS_CLIENT_ID
npx wrangler secret put ACCESS_CLIENT_SECRET
npx wrangler secret put ACCESS_TOKEN_URL
npx wrangler secret put ACCESS_AUTHORIZATION_URL
npx wrangler secret put ACCESS_JWKS_URL
npx wrangler secret put COOKIE_ENCRYPTION_KEY
```

Document `/health`, OAuth connection, token/Yahoo-password rotation, Worker rollback, and the prohibition on pasting credentials into ChatGPT.

- [ ] **Step 4: Run the complete local gate**

Run: `npm run verify`

Expected: formatting, lint, type checking, all tests, and Wrangler dry-run pass.

- [ ] **Step 5: Commit CI and operations docs**

```powershell
git add .github/workflows/ci.yml README.md SECURITY.md .env.example package-lock.json
git rm Dockerfile
git commit -m "docs: add Cloudflare Worker operations"
```

### Task 7: Provision Cloudflare Resources and Deploy in Fail-Closed Stages

**Files:**

- Modify: `wrangler.jsonc` with the actual created KV namespace ID
- No secret-bearing files created or modified

**Interfaces:**

- Consumes the locally stored Cloudflare account identifier and restricted API token without printing them.
- Produces the `OAUTH_KV` namespace, Worker deployment, Access for SaaS app, and production Worker secrets.

- [ ] **Step 1: Validate deployment credentials without displaying them**

Load the locally stored values into process-scoped `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN`, then run:

```powershell
npx wrangler whoami
```

Expected: the intended account is listed. If the token lacks Workers Scripts, KV, or Access permissions, stop and request only the missing permission; do not replace it with a broad token.

- [ ] **Step 2: Create the OAuth KV namespace**

Run: `npx wrangler kv namespace create OAUTH_KV`

Copy the exact returned namespace ID into the `OAUTH_KV` binding in `wrangler.jsonc`, run `git diff --check`, then commit:

```powershell
git add wrangler.jsonc
git commit -m "infra: bind OAuth KV namespace"
```

- [ ] **Step 3: Deploy without Yahoo secrets and verify fail-closed behavior**

Run:

```powershell
npm run verify
npx wrangler deploy
```

Verify:

```powershell
Invoke-RestMethod https://yahoo-mail-chatgpt-mcp.workers.dev/health
Invoke-WebRequest -Method Post https://yahoo-mail-chatgpt-mcp.workers.dev/mcp -SkipHttpErrorCheck
```

Expected: health is exactly `{status: ok}` and unauthenticated MCP is `401`; no mailbox call is possible.

- [ ] **Step 4: Create the Access for SaaS OIDC application**

In Cloudflare Zero Trust, create one SaaS OIDC application named `Yahoo Mail MCP`, set redirect URL to `https://yahoo-mail-chatgpt-mcp.workers.dev/callback`, enable authorization code plus refresh tokens, and apply an allow policy for only the owner's chosen email identity. Keep generic “Protect with Cloudflare Access” off because the Worker implements the MCP OAuth flow.

- [ ] **Step 5: Store Access values and a generated cookie key as Worker secrets**

Run only the six Access-related `wrangler secret put` commands from Task 6 (`ACCESS_CLIENT_ID`, `ACCESS_CLIENT_SECRET`, `ACCESS_TOKEN_URL`, `ACCESS_AUTHORIZATION_URL`, `ACCESS_JWKS_URL`, and `COOKIE_ENCRYPTION_KEY`). Generate `COOKIE_ENCRYPTION_KEY` in memory with a cryptographically secure 32-byte random value. Do not echo it or persist it locally.

- [ ] **Step 6: Verify OAuth before adding Yahoo credentials**

Use MCP Inspector Quick OAuth Flow against `https://yahoo-mail-chatgpt-mcp.workers.dev/mcp`. Expected: the allowlisted identity can approve and list exactly five tools; another identity is denied. Tool calls fail with a generic configuration/upstream error until Yahoo secrets are present.

- [ ] **Step 7: Add Yahoo credentials interactively**

Run:

```powershell
npx wrangler secret put YAHOO_EMAIL
npx wrangler secret put YAHOO_APP_PASSWORD
```

The current local `.env` does not expose these as parsable named variables. If they are not otherwise available locally, stop and ask the user to enter them into Wrangler's hidden prompt; never request them in chat.

- [ ] **Step 8: Run minimum-exposure production smoke tests**

Invoke `list_folders`, then `list_emails` with `limit: 1`, then `read_email` only on a deliberately selected non-sensitive test message. Confirm outputs are sanitized and Cloudflare logs show only route/tool/outcome metadata.

### Task 8: Connect ChatGPT and Complete the Security Review

**Files:**

- Modify: `README.md` only if the observed ChatGPT flow differs from documented official behavior
- Create: `docs/deployment-verification.md`

**Interfaces:**

- Produces a user-visible ChatGPT custom MCP connection and a secret-free verification record.

- [ ] **Step 1: Connect the deployed endpoint in ChatGPT**

Add `https://yahoo-mail-chatgpt-mcp.workers.dev/mcp` through ChatGPT's supported custom MCP/app flow. Complete OAuth in the browser using the allowlisted Cloudflare Access identity.

- [ ] **Step 2: Verify tool discovery and a sanitized morning brief**

Confirm ChatGPT discovers exactly five read-only tools. Run `get_morning_brief_emails` with `hours: 24`, `limit: 3`, and `unreadOnly: false`. Inspect for redaction without copying mailbox output into the repository or task transcript.

- [ ] **Step 3: Run final repository and log secret scans**

Run:

```powershell
git ls-files | rg "(^|/)(\.env|.*secret.*|.*credential.*|.*token.*)$"
rg -n --hidden -g '!node_modules/**' -g '!dist/**' "YAHOO_APP_PASSWORD=|CLOUDFLARE_API_TOKEN=|ACCESS_CLIENT_SECRET=" .
npx wrangler tail yahoo-mail-chatgpt-mcp --format json
```

Expected: no tracked secret files or assigned secret values; sampled logs contain no mailbox data, identities, credentials, OAuth codes, or tokens.

- [ ] **Step 4: Exercise rollback with a non-production version**

Upload a no-op version, verify it, and use Cloudflare version rollback to restore the previously verified version. Do not rotate live credentials during this exercise.

- [ ] **Step 5: Record secret-free verification evidence**

`docs/deployment-verification.md` records commit SHA, Worker version IDs, test command outcomes, endpoint path, OAuth pass/fail, exact tool names, rollback result, and remaining risks. It contains no mailbox content, user email, account IDs, KV IDs, or secrets.

- [ ] **Step 6: Run final gates and commit**

Run:

```powershell
npm run verify
git diff --check
git status --short
```

```powershell
git add README.md docs/deployment-verification.md
git commit -m "docs: record Cloudflare deployment verification"
```
