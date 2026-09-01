import express from "express";
import request from "supertest";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";
import { sha256Token } from "../src/oauth/crypto.js";
import { requireMcpBearer } from "../src/oauth/middleware.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

const origin = "https://yahoo-mail-mcp.onrender.com";
const resource = `${origin}/mcp`;
const challenge = `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`;
const validToken = "a".repeat(43);

function createTestApp(now = Date.now()) {
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
  const store = new InMemoryOAuthStore(now);
  const app = express();
  app.all("/mcp", requireMcpBearer(config, store), (_req, res) => {
    res.json({ auth: res.locals.auth, localKeys: Object.keys(res.locals) });
  });
  return { app, store };
}

async function seedAccessToken(
  store: InMemoryOAuthStore,
  overrides: Partial<{
    clientId: string;
    resource: string;
    scope: string;
    expiresAt: number;
  }> = {},
) {
  await store.createAccessToken(
    sha256Token(validToken),
    {
      clientId: "registered-public-client",
      resource,
      scope: "mcp:read",
      expiresAt: Date.now() + 15 * 60 * 1_000,
      ...overrides,
    },
    15 * 60,
  );
}

describe("MCP bearer authorization", () => {
  it.each([
    ["missing credentials", undefined],
    ["wrong scheme", `Basic ${validToken}`],
    ["malformed bearer", "Bearer not-opaque"],
    ["extra bearer value", `Bearer ${validToken} extra`],
    ["unknown bearer", `Bearer ${"z".repeat(43)}`],
  ])(
    "rejects %s with the protected-resource challenge",
    async (_name, authorization) => {
      const { app } = createTestApp();
      let pending = request(app).post("/mcp");
      if (authorization) pending = pending.set("Authorization", authorization);

      const response = await pending;

      expect(response.status).toBe(401);
      expect(response.body).toEqual({ error: "unauthorized" });
      expect(response.headers["www-authenticate"]).toBe(challenge);
    },
  );

  it("rejects an expired access token", async () => {
    const now = Date.now();
    const { app, store } = createTestApp(now);
    await seedAccessToken(store, { expiresAt: now - 1 });

    const response = await request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${validToken}`);

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(challenge);
  });

  it("rejects an access token bound to another resource", async () => {
    const { app, store } = createTestApp();
    await seedAccessToken(store, { resource: `${origin}/other` });

    const response = await request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${validToken}`);

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(challenge);
  });

  it("rejects an access token without the exact mcp:read scope", async () => {
    const { app, store } = createTestApp();
    await seedAccessToken(store, { scope: "mcp:write" });

    const response = await request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${validToken}`);

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(challenge);
  });

  it("rejects query-string tokens even when the header token is valid", async () => {
    const { app, store } = createTestApp();
    await seedAccessToken(store);

    const response = await request(app)
      .post(`/mcp?access_token=${"z".repeat(43)}`)
      .set("Authorization", `Bearer ${validToken}`);

    expect(response.status).toBe(401);
    expect(response.headers["www-authenticate"]).toBe(challenge);
  });

  it("attaches only clientId and scope for a valid exact-resource token", async () => {
    const { app, store } = createTestApp();
    await seedAccessToken(store);

    const response = await request(app)
      .post("/mcp")
      .set("Authorization", `Bearer ${validToken}`);

    expect(response.status).toBe(200);
    expect(response.body).toEqual({
      auth: { clientId: "registered-public-client", scope: "mcp:read" },
      localKeys: ["auth"],
    });
    expect(JSON.stringify(response.body)).not.toContain(resource);
    expect(JSON.stringify(response.body)).not.toContain("expiresAt");
  });
});
