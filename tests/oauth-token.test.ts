import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { pkceChallenge, sha256Token } from "../src/oauth/crypto.js";
import type { AuthorizationCodeRecord } from "../src/oauth/types.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

const origin = "https://yahoo-mail-mcp.onrender.com";
const resource = `${origin}/mcp`;
const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
const clientId = "registered-public-client";
const verifier = "v".repeat(43);

function createTestApp(now = Date.now()) {
  const store = new InMemoryOAuthStore(now);
  const config = loadConfig({
    YAHOO_EMAIL: "user@example.com",
    YAHOO_APP_PASSWORD: "private-app-password",
    REDIS_URL: "redis://private-redis.internal:6379",
    PUBLIC_ORIGIN: origin,
    MCP_LOGIN_PASSPHRASE_SCRYPT:
      "scrypt$16384$8$1$c2FsdC1mb3ItdGVzdA$3YQqZrjE8xVgkYMi4Z0ddZ6AiBIrrRD5txi1QGcVPTk",
    OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
    HOST: "127.0.0.1",
    ALLOWED_HOSTS: "localhost,127.0.0.1",
  });
  const app = createApp(config, {
    oauthStore: store,
    createMcpServer: () => {
      throw new Error("MCP server must not be created for a token request");
    },
  });
  return { app, store };
}

async function seedCode(
  store: InMemoryOAuthStore,
  code: string,
  overrides: Partial<AuthorizationCodeRecord> = {},
) {
  await store.createAuthorizationCode(
    sha256Token(code),
    {
      clientId,
      redirectUri,
      resource,
      codeChallenge: await pkceChallenge(verifier),
      scope: "mcp:read",
      ...overrides,
    },
    300,
  );
}

function authorizationCodeForm(code: string) {
  return {
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    redirect_uri: redirectUri,
    resource,
    code_verifier: verifier,
  };
}

async function exchangeCode(
  app: ReturnType<typeof createTestApp>["app"],
  store: InMemoryOAuthStore,
  suffix = "a",
) {
  const code = suffix.repeat(43);
  await seedCode(store, code);
  return request(app)
    .post("/token")
    .type("form")
    .send(authorizationCodeForm(code));
}

describe("OAuth authorization-code token exchange", () => {
  it("requires an application/x-www-form-urlencoded request", async () => {
    const { app, store } = createTestApp();
    const code = "a".repeat(43);
    await seedCode(store, code);

    const response = await request(app)
      .post("/token")
      .send(authorizationCodeForm(code));

    expect(response.status).toBe(415);
    expect(response.body).toEqual({ error: "invalid_request" });
  });

  it.each([
    ["missing grant type", { grant_type: undefined }, "invalid_request"],
    [
      "unsupported grant type",
      { grant_type: "client_credentials" },
      "unsupported_grant_type",
    ],
  ])("rejects %s", async (_name, override, error) => {
    const { app, store } = createTestApp();
    const code = "b".repeat(43);
    await seedCode(store, code);
    const form = { ...authorizationCodeForm(code), ...override };

    const response = await request(app).post("/token").type("form").send(form);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error });
  });

  it.each([
    ["client", { client_id: "different-client" }],
    ["redirect URI", { redirect_uri: "https://example.test/callback" }],
    ["resource", { resource: `${origin}/other` }],
    ["verifier syntax", { code_verifier: "too-short" }],
    ["PKCE proof", { code_verifier: "w".repeat(43) }],
  ])(
    "consumes a code before rejecting an invalid %s binding",
    async (_name, override) => {
      const { app, store } = createTestApp();
      const code = "c".repeat(43);
      await seedCode(store, code);

      const rejected = await request(app)
        .post("/token")
        .type("form")
        .send({ ...authorizationCodeForm(code), ...override });
      const retried = await request(app)
        .post("/token")
        .type("form")
        .send(authorizationCodeForm(code));

      expect(rejected.status).toBe(400);
      expect(rejected.body).toEqual({ error: "invalid_grant" });
      expect(retried.status).toBe(400);
      expect(retried.body).toEqual({ error: "invalid_grant" });
    },
  );

  it("returns SHA-256-indexed opaque access and refresh tokens", async () => {
    const { app, store } = createTestApp();

    const response = await exchangeCode(app, store, "d");

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.headers.pragma).toBe("no-cache");
    expect(response.body).toMatchObject({
      token_type: "Bearer",
      expires_in: 900,
      scope: "mcp:read",
    });
    expect(response.body.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(response.body.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      await store.getAccessToken(sha256Token(response.body.access_token)),
    ).toMatchObject({
      clientId,
      resource,
      scope: "mcp:read",
    });
    expect(await store.getAccessToken(response.body.access_token)).toBeNull();
  });
});

describe("OAuth refresh-token exchange", () => {
  it("rotates refresh and access tokens while preserving the fixed family expiry", async () => {
    const startedAt = Date.now();
    const { app, store } = createTestApp(startedAt);
    const initial = await exchangeCode(app, store, "e");
    const firstRefresh = initial.body.refresh_token as string;

    const rotated = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: firstRefresh,
      client_id: clientId,
      resource,
    });

    expect(rotated.status).toBe(200);
    expect(rotated.body).toMatchObject({
      token_type: "Bearer",
      expires_in: 900,
      scope: "mcp:read",
    });
    expect(rotated.body.access_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(rotated.body.refresh_token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(rotated.body.access_token).not.toBe(initial.body.access_token);
    expect(rotated.body.refresh_token).not.toBe(firstRefresh);

    store.advanceBy(30 * 24 * 60 * 60 * 1_000);
    const expired = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: rotated.body.refresh_token,
      client_id: clientId,
      resource,
    });
    expect(expired.status).toBe(400);
    expect(expired.body).toEqual({ error: "invalid_grant" });
  });

  it("revokes the refresh family when a rotated token is replayed", async () => {
    const { app, store } = createTestApp();
    const initial = await exchangeCode(app, store, "f");
    const oldRefresh = initial.body.refresh_token as string;
    const rotated = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: oldRefresh,
      client_id: clientId,
      resource,
    });

    const replay = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: oldRefresh,
      client_id: clientId,
      resource,
    });
    const newest = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: rotated.body.refresh_token,
      client_id: clientId,
      resource,
    });

    expect(replay.status).toBe(400);
    expect(replay.body).toEqual({ error: "invalid_grant" });
    expect(newest.status).toBe(400);
    expect(newest.body).toEqual({ error: "invalid_grant" });
  });

  it.each([
    ["missing token", { refresh_token: undefined }],
    ["malformed token", { refresh_token: "not-opaque" }],
    ["unknown token", { refresh_token: "z".repeat(43) }],
  ])("uses invalid_grant for a %s", async (_name, override) => {
    const { app } = createTestApp();
    const response = await request(app)
      .post("/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        client_id: clientId,
        resource,
        ...override,
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_grant" });
  });

  it.each([
    ["client", { client_id: "different-client" }],
    ["resource", { resource: `${origin}/other` }],
    ["scope", { scope: "mcp:write" }],
  ])("requires the exact stored %s binding", async (_name, override) => {
    const { app, store } = createTestApp();
    const initial = await exchangeCode(app, store, "g");

    const response = await request(app)
      .post("/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: initial.body.refresh_token,
        client_id: clientId,
        resource,
        ...override,
      });

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_grant" });

    const retry = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: initial.body.refresh_token,
      client_id: clientId,
      resource,
    });
    expect(retry.status).toBe(200);
  });
});
