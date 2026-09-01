import { scryptSync } from "node:crypto";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { sha256Token } from "../src/oauth/crypto.js";
import type {
  AuthorizationCodeRecord,
  AuthorizationTransaction,
  PromoteClientAndCreateAuthorizationCodeResult,
  RegisteredClient,
} from "../src/oauth/types.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

const origin = "https://yahoo-mail-mcp.onrender.com";
const resource = `${origin}/mcp`;
const redirectUri = "https://client.example.test/oauth/callback";
const client: RegisteredClient = {
  clientId: "registered-client",
  redirectUris: [redirectUri],
  grantTypes: ["authorization_code", "refresh_token"],
  responseTypes: ["code"],
  tokenEndpointAuthMethod: "none",
  scope: "mcp:read",
};
const codeChallenge = "A".repeat(43);
const passphrase = "correct horse battery staple";
const salt = Buffer.from("authorization-test-salt");
const passphraseDigest = `scrypt$16384$8$1$${salt.toString("base64url")}$${scryptSync(
  passphrase,
  salt,
  32,
  {
    N: 16_384,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  },
).toString("base64url")}`;

class CapturingStore extends InMemoryOAuthStore {
  readonly createdTransactions: Array<{
    id: string;
    value: AuthorizationTransaction;
    ttlSeconds: number;
  }> = [];
  readonly createdCodes: Array<{
    digest: string;
    value: AuthorizationCodeRecord;
    ttlSeconds: number;
  }> = [];
  readonly rateLimitCalls: Array<{ key: string; ttlSeconds: number }> = [];
  readonly reservationCalls: Array<{
    keys: readonly string[];
    reservationId: string;
    limit: number;
    ttlSeconds: number;
  }> = [];
  readonly releaseCalls: Array<{
    keys: readonly string[];
    reservationId: string;
  }> = [];

  override async createTransaction(
    id: string,
    value: AuthorizationTransaction,
    ttlSeconds: number,
  ): Promise<void> {
    this.createdTransactions.push({
      id,
      value: structuredClone(value),
      ttlSeconds,
    });
    await super.createTransaction(id, value, ttlSeconds);
  }

  override async createAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<void> {
    this.createdCodes.push({
      digest,
      value: structuredClone(value),
      ttlSeconds,
    });
    await super.createAuthorizationCode(digest, value, ttlSeconds);
  }

  override async promoteClientAndCreateAuthorizationCode(
    digest: string,
    value: AuthorizationCodeRecord,
    ttlSeconds: number,
  ): Promise<PromoteClientAndCreateAuthorizationCodeResult> {
    const result = await super.promoteClientAndCreateAuthorizationCode(
      digest,
      value,
      ttlSeconds,
    );
    if (result.status === "promoted") {
      this.createdCodes.push({
        digest,
        value: structuredClone(value),
        ttlSeconds,
      });
    }
    return result;
  }

  override async incrementRateLimit(
    key: string,
    ttlSeconds: number,
  ): Promise<number> {
    this.rateLimitCalls.push({ key, ttlSeconds });
    return super.incrementRateLimit(key, ttlSeconds);
  }

  override async reserveRateLimit(
    keys: readonly string[],
    reservationId: string,
    limit: number,
    ttlSeconds: number,
  ): Promise<boolean> {
    this.reservationCalls.push({
      keys: [...keys],
      reservationId,
      limit,
      ttlSeconds,
    });
    return super.reserveRateLimit(keys, reservationId, limit, ttlSeconds);
  }

  override async releaseRateLimit(
    keys: readonly string[],
    reservationId: string,
  ): Promise<void> {
    this.releaseCalls.push({ keys: [...keys], reservationId });
    await super.releaseRateLimit(keys, reservationId);
  }
}

function createTestApp(store = new CapturingStore()) {
  const config = loadConfig({
    YAHOO_EMAIL: "private-owner@example.com",
    YAHOO_APP_PASSWORD: "private-app-password",
    REDIS_URL: "redis://private-redis.internal:6379",
    PUBLIC_ORIGIN: origin,
    MCP_LOGIN_PASSPHRASE_SCRYPT: passphraseDigest,
    OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
    HOST: "127.0.0.1",
    ALLOWED_HOSTS: "localhost,127.0.0.1",
  });
  const app = createApp(config, {
    oauthStore: store,
    createMcpServer: () => {
      throw new Error("MCP server must not be created for authorization");
    },
  });
  return { app, config, store };
}

function validAuthorizationQuery(
  overrides: Record<string, string | undefined> = {},
): Record<string, string> {
  const values: Record<string, string | undefined> = {
    response_type: "code",
    client_id: client.clientId,
    redirect_uri: redirectUri,
    resource,
    state: "original-state",
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    scope: "mcp:read",
    ...overrides,
  };
  return Object.fromEntries(
    Object.entries(values).filter((entry): entry is [string, string] => {
      return entry[1] !== undefined;
    }),
  );
}

async function beginAuthorization(
  app: ReturnType<typeof createTestApp>["app"],
): Promise<{ cookie: string; csrf: string; transactionId: string }> {
  const response = await request(app)
    .get("/authorize")
    .query(validAuthorizationQuery());
  expect(response.status).toBe(200);
  const cookie = response.headers["set-cookie"]?.[0];
  expect(cookie).toEqual(expect.any(String));
  const transactionId = /name="transaction_id" value="([^"]+)"/.exec(
    response.text,
  )?.[1];
  const csrf = /name="csrf" value="([^"]+)"/.exec(response.text)?.[1];
  expect(transactionId).toEqual(expect.any(String));
  expect(csrf).toEqual(expect.any(String));
  return {
    cookie: cookie!.split(";", 1)[0]!,
    csrf: csrf!,
    transactionId: transactionId!,
  };
}

async function postAuthorization(
  app: ReturnType<typeof createTestApp>["app"],
  form: { cookie: string; csrf: string; transactionId: string },
  overrides: Record<string, string> = {},
) {
  return request(app)
    .post("/authorize")
    .set("Cookie", form.cookie)
    .type("form")
    .send({
      transaction_id: form.transactionId,
      csrf: form.csrf,
      decision: "allow",
      passphrase,
      ...overrides,
    });
}

describe("OAuth authorization request", () => {
  it("creates a ten-minute one-time transaction for an exact valid request", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);

    const response = await request(app)
      .get("/authorize")
      .query(validAuthorizationQuery());

    expect(response.status).toBe(200);
    expect(store.createdTransactions).toHaveLength(1);
    expect(store.createdTransactions[0]).toMatchObject({
      ttlSeconds: 600,
      value: {
        clientId: client.clientId,
        redirectUri,
        resource,
        state: "original-state",
        codeChallenge,
        scope: "mcp:read",
      },
    });
    const transactionId = store.createdTransactions[0]!.id;
    expect(await store.consumeTransaction(transactionId)).not.toBeNull();
    expect(await store.consumeTransaction(transactionId)).toBeNull();
  });

  it.each([
    ["response type", { response_type: "token" }],
    ["missing response type", { response_type: undefined }],
    ["unknown client", { client_id: "unknown-client" }],
    ["resource", { resource: `${origin}/other` }],
    ["missing state", { state: undefined }],
    ["empty state", { state: "" }],
    ["oversized state", { state: "s".repeat(1_025) }],
    ["challenge method", { code_challenge_method: "plain" }],
    ["challenge syntax", { code_challenge: "not-a-sha256-challenge" }],
    ["noncanonical challenge", { code_challenge: `${"A".repeat(42)}B` }],
    ["scope", { scope: "mcp:write" }],
    ["missing scope", { scope: undefined }],
  ])(
    "rejects an invalid %s without creating state",
    async (_name, override) => {
      const { app, store } = createTestApp();
      await store.registerClient(client);

      const response = await request(app)
        .get("/authorize")
        .query(validAuthorizationQuery(override));

      expect(response.status).toBe(400);
      expect(response.headers.location).toBeUndefined();
      expect(response.body).toEqual({ error: "invalid_request" });
      expect(store.createdTransactions).toHaveLength(0);
    },
  );

  it("never redirects an unregistered redirect URI", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);

    const response = await request(app)
      .get("/authorize")
      .query(
        validAuthorizationQuery({
          redirect_uri: "https://attacker.example.test/callback",
        }),
      );

    expect(response.status).toBe(400);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toEqual({ error: "invalid_request" });
  });

  it("renders a secret-free hardened minimal login form", async () => {
    const { app, store } = createTestApp();
    await store.registerClient({
      ...client,
      clientName: '<script src="https://attacker.test/x.js"></script>',
    });

    const response = await request(app)
      .get("/authorize")
      .query(
        validAuthorizationQuery({ state: "<img src=x onerror=alert(1)>" }),
      );

    expect(response.status).toBe(200);
    expect(response.headers["content-security-policy"]).toBe(
      "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    );
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers["set-cookie"]?.[0]).toMatch(
      /^__Host-mcp_oauth_csrf=[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+; Path=\/; HttpOnly; Secure; SameSite=Lax$/,
    );
    expect(response.text).toContain('type="password" name="passphrase"');
    expect(response.text).toContain('name="decision" value="allow"');
    expect(response.text).toContain('name="decision" value="deny"');
    expect(response.text).not.toContain("<script");
    expect(response.text).not.toContain("<img");
    expect(response.text).not.toContain("private-owner@example.com");
    expect(response.text).not.toContain("private-redis.internal");
    expect(response.text).not.toContain("yahoo-mail-mcp.onrender.com");
  });

  it("accepts a same-origin browser form POST", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const allowed = await beginAuthorization(app);

    const allowedResponse = await request(app)
      .post("/authorize")
      .set("Origin", origin)
      .set("Cookie", allowed.cookie)
      .type("form")
      .send({
        transaction_id: allowed.transactionId,
        csrf: allowed.csrf,
        decision: "deny",
      });

    expect(allowedResponse.status).toBe(302);
    expect(allowedResponse.headers.location).toBe(
      `${redirectUri}?error=access_denied&state=original-state`,
    );
  });

  it("rejects a hostile browser origin before consuming the transaction", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const rejected = await beginAuthorization(app);
    const rejectedResponse = await request(app)
      .post("/authorize")
      .set("Origin", "https://attacker.example.test")
      .set("Cookie", rejected.cookie)
      .type("form")
      .send({
        transaction_id: rejected.transactionId,
        csrf: rejected.csrf,
        decision: "deny",
      });

    expect(rejectedResponse.status).toBe(403);
    expect(rejectedResponse.headers.location).toBeUndefined();
    expect(
      await store.consumeTransaction(rejected.transactionId),
    ).not.toBeNull();
  });
});

describe("OAuth authorization decision", () => {
  it("rejects forms larger than 16 KiB", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const form = await beginAuthorization(app);

    const response = await postAuthorization(app, form, {
      passphrase: "x".repeat(16 * 1_024),
    });

    expect(response.status).toBe(413);
    expect(response.body).toEqual({ error: "request_too_large" });
  });

  it("rejects a CSRF mismatch and consumes the transaction", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const form = await beginAuthorization(app);

    const response = await postAuthorization(app, form, { csrf: "wrong" });

    expect(response.status).toBe(400);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toEqual({ error: "invalid_request" });
    expect(await store.consumeTransaction(form.transactionId)).toBeNull();
  });

  it("rejects a signed CSRF value copied from another transaction", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const first = await beginAuthorization(app);
    const second = await beginAuthorization(app);

    const response = await postAuthorization(app, {
      cookie: second.cookie,
      csrf: second.csrf,
      transactionId: first.transactionId,
    });

    expect(response.status).toBe(400);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toEqual({ error: "invalid_request" });
    expect(store.createdCodes).toHaveLength(0);
  });

  it("rejects expired and consumed transactions", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client, 600);
    const expired = await beginAuthorization(app);
    store.advanceBy(10 * 60 * 1_000);

    const expiredResponse = await postAuthorization(app, expired);
    expect(expiredResponse.status).toBe(400);
    expect(expiredResponse.body).toEqual({ error: "invalid_request" });
    expect(await store.getClient(client.clientId)).toBeNull();

    await store.registerClient(client);
    const consumed = await beginAuthorization(app);
    await store.consumeTransaction(consumed.transactionId);
    const consumedResponse = await postAuthorization(app, consumed);
    expect(consumedResponse.status).toBe(400);
    expect(consumedResponse.body).toEqual({ error: "invalid_request" });
  });

  it("rejects an incorrect passphrase without issuing a code", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client, 600);
    const form = await beginAuthorization(app);

    const response = await postAuthorization(app, form, {
      passphrase: "incorrect passphrase",
    });

    expect(response.status).toBe(403);
    expect(response.headers.location).toBeUndefined();
    expect(response.body).toEqual({ error: "access_denied" });
    expect(store.createdCodes).toHaveLength(0);
    store.advanceBy(600_000);
    expect(await store.getClient(client.clientId)).toBeNull();
  });

  it("does not charge successful authorizations against failure buckets", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const responses = [];

    for (let index = 0; index < 6; index += 1) {
      const form = await beginAuthorization(app);
      responses.push(
        await request(app)
          .post("/authorize")
          .set("X-Forwarded-For", "198.51.100.42")
          .set("Cookie", form.cookie)
          .type("form")
          .send({
            transaction_id: form.transactionId,
            csrf: form.csrf,
            decision: "allow",
            passphrase,
          }),
      );
      expect(await store.consumeTransaction(form.transactionId)).toBeNull();
    }

    expect(responses.every((response) => response.status === 302)).toBe(true);
    expect(store.createdCodes).toHaveLength(6);
    expect(store.rateLimitCalls).toHaveLength(0);
    expect(store.reservationCalls).toHaveLength(6);
    expect(store.releaseCalls).toHaveLength(6);
  });

  it("atomically admits only five concurrent attempts and releases successful reservations", async () => {
    const { app, config, store } = createTestApp();
    await store.registerClient(client);
    let digestReads = 0;
    Object.defineProperty(config, "passphraseDigest", {
      configurable: true,
      get: () => {
        digestReads += 1;
        return passphraseDigest;
      },
    });
    const forms = await Promise.all(
      Array.from({ length: 6 }, () => beginAuthorization(app)),
    );

    const responses = await Promise.all(
      forms.map((form) =>
        request(app)
          .post("/authorize")
          .set("X-Forwarded-For", "198.51.100.42")
          .set("Cookie", form.cookie)
          .type("form")
          .send({
            transaction_id: form.transactionId,
            csrf: form.csrf,
            decision: "allow",
            passphrase,
          }),
      ),
    );

    expect(
      responses.filter((response) => response.status === 302),
    ).toHaveLength(5);
    expect(
      responses.filter((response) => response.status === 429),
    ).toHaveLength(1);
    expect(digestReads).toBe(5);
    expect(store.createdCodes).toHaveLength(5);
    expect(store.rateLimitCalls).toHaveLength(0);
    expect(store.reservationCalls).toHaveLength(6);
    expect(store.releaseCalls).toHaveLength(5);

    const later = await beginAuthorization(app);
    const laterResponse = await postAuthorization(app, later);
    expect(laterResponse.status).toBe(302);
    expect(digestReads).toBe(6);
  });

  it("records a failed one-time transaction and trusted IP for fifteen minutes", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client);
    const form = await beginAuthorization(app);

    const response = await request(app)
      .post("/authorize")
      .set("X-Forwarded-For", "198.51.100.42")
      .set("Cookie", form.cookie)
      .type("form")
      .send({
        transaction_id: form.transactionId,
        csrf: form.csrf,
        decision: "allow",
        passphrase: "incorrect passphrase",
      });

    expect(response.status).toBe(403);
    expect(store.rateLimitCalls).toHaveLength(0);
    expect(store.reservationCalls).toEqual([
      {
        keys: [
          `authorization:transaction:${sha256Token(form.transactionId)}`,
          `authorization:ip:${sha256Token("198.51.100.42")}`,
        ],
        reservationId: sha256Token(form.transactionId),
        limit: 5,
        ttlSeconds: 900,
      },
    ]);
    expect(store.releaseCalls).toHaveLength(0);
    expect(JSON.stringify(store.reservationCalls)).not.toContain(
      form.transactionId,
    );
    expect(JSON.stringify(store.reservationCalls)).not.toContain(
      "198.51.100.42",
    );
  });

  it("rejects a correct sixth attempt before passphrase verification after five IP failures", async () => {
    const { app, config, store } = createTestApp();
    await store.registerClient(client);
    const responses = [];
    for (let index = 0; index < 5; index += 1) {
      const form = await beginAuthorization(app);
      responses.push(
        await request(app)
          .post("/authorize")
          .set("X-Forwarded-For", "198.51.100.42")
          .set("Cookie", form.cookie)
          .type("form")
          .send({
            transaction_id: form.transactionId,
            csrf: form.csrf,
            decision: "allow",
            passphrase: "incorrect passphrase",
          }),
      );
    }

    expect(responses.every((response) => response.status === 403)).toBe(true);
    expect(store.rateLimitCalls).toHaveLength(0);
    expect(store.reservationCalls).toHaveLength(5);
    expect(store.releaseCalls).toHaveLength(0);

    Object.defineProperty(config, "passphraseDigest", {
      configurable: true,
      get: () => {
        throw new Error("passphrase verification must not run after lockout");
      },
    });
    const lockedTransaction = await beginAuthorization(app);
    const lockedResponse = await request(app)
      .post("/authorize")
      .set("X-Forwarded-For", "198.51.100.42")
      .set("Cookie", lockedTransaction.cookie)
      .type("form")
      .send({
        transaction_id: lockedTransaction.transactionId,
        csrf: lockedTransaction.csrf,
        decision: "allow",
        passphrase,
      });

    expect(lockedResponse.status).toBe(429);
    expect(lockedResponse.body).toEqual({ error: "rate_limited" });
    expect(store.createdCodes).toHaveLength(0);
    expect(store.rateLimitCalls).toHaveLength(0);
    expect(store.reservationCalls).toHaveLength(6);
    expect(store.releaseCalls).toHaveLength(0);
    expect(
      await store.consumeTransaction(lockedTransaction.transactionId),
    ).toBeNull();
  });

  it("redirects an explicit denial with only the OAuth error and original state", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client, 600);
    const form = await beginAuthorization(app);

    const response = await postAuthorization(app, form, {
      decision: "deny",
      passphrase: "",
    });

    expect(response.status).toBe(302);
    const location = new URL(response.headers.location!);
    expect(location.origin + location.pathname).toBe(redirectUri);
    expect(Object.fromEntries(location.searchParams)).toEqual({
      error: "access_denied",
      state: "original-state",
    });
    store.advanceBy(600_000);
    expect(await store.getClient(client.clientId)).toBeNull();
  });

  it("issues a five-minute SHA-256-indexed bound code and redirects only code and state", async () => {
    const { app, store } = createTestApp();
    await store.registerClient(client, 600);
    const form = await beginAuthorization(app);

    const response = await postAuthorization(app, form);

    expect(response.status).toBe(302);
    const location = new URL(response.headers.location!);
    expect(location.origin + location.pathname).toBe(redirectUri);
    expect([...location.searchParams.keys()].sort()).toEqual(["code", "state"]);
    expect(location.searchParams.get("state")).toBe("original-state");
    const code = location.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(store.createdCodes).toEqual([
      {
        digest: sha256Token(code!),
        ttlSeconds: 300,
        value: {
          clientId: client.clientId,
          redirectUri,
          resource,
          codeChallenge,
          scope: "mcp:read",
        },
      },
    ]);
    expect(JSON.stringify(store.createdCodes)).not.toContain(code);
    expect(await store.consumeTransaction(form.transactionId)).toBeNull();
    store.advanceBy(600_000);
    expect(await store.getClient(client.clientId)).not.toBeNull();
  });
});
