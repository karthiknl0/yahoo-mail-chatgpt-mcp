import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

function createTestApp(store = new InMemoryOAuthStore()) {
  const app = createApp(
    loadConfig({
      YAHOO_EMAIL: "user@example.com",
      YAHOO_APP_PASSWORD: "app-password-value",
      REDIS_URL: "redis://127.0.0.1:6379",
      PUBLIC_ORIGIN: "https://yahoo-mail-mcp.onrender.com",
      MCP_LOGIN_PASSPHRASE_SCRYPT:
        "scrypt$16384$8$1$c2FsdC1mb3ItdGVzdA$3YQqZrjE8xVgkYMi4Z0ddZ6AiBIrrRD5txi1QGcVPTk",
      OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
      HOST: "127.0.0.1",
      ALLOWED_HOSTS: "localhost,127.0.0.1",
    }),
    {
      oauthStore: store,
      createMcpServer: () => {
        throw new Error("MCP server must not be created for registration");
      },
    },
  );
  return { app, store };
}

const publicClient = {
  client_name: "MCP Inspector",
  redirect_uris: ["http://127.0.0.1:6274/oauth/callback"],
  grant_types: ["authorization_code", "refresh_token"],
  response_types: ["code"],
  token_endpoint_auth_method: "none",
};

describe("dynamic client registration", () => {
  it("registers a bounded public client without a secret", async () => {
    const { app, store } = createTestApp();
    const response = await request(app).post("/register").send(publicClient);

    expect(response.status).toBe(201);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      redirect_uris: publicClient.redirect_uris,
      client_name: publicClient.client_name,
      grant_types: publicClient.grant_types,
      response_types: publicClient.response_types,
      token_endpoint_auth_method: "none",
    });
    expect(response.body.client_id).toEqual(expect.any(String));
    expect(response.body).not.toHaveProperty("client_secret");
    expect(await store.getClient(response.body.client_id)).toMatchObject({
      clientId: response.body.client_id,
      redirectUris: publicClient.redirect_uris,
      clientName: publicClient.client_name,
      tokenEndpointAuthMethod: "none",
    });
  });

  it("creates an unpredictable client id for each registration", async () => {
    const { app } = createTestApp();
    const [first, second] = await Promise.all([
      request(app).post("/register").send(publicClient),
      request(app).post("/register").send(publicClient),
    ]);

    expect(first.status).toBe(201);
    expect(second.status).toBe(201);
    expect(first.body.client_id).not.toBe(second.body.client_id);
  });

  it.each([
    ["missing redirect URIs", { ...publicClient, redirect_uris: undefined }],
    [
      "wildcard",
      { ...publicClient, redirect_uris: ["https://*.example.test/callback"] },
    ],
    [
      "wildcard path",
      { ...publicClient, redirect_uris: ["https://client.example/*/callback"] },
    ],
    [
      "wildcard query",
      {
        ...publicClient,
        redirect_uris: ["https://client.example/callback?next=*"],
      },
    ],
    [
      "fragment",
      {
        ...publicClient,
        redirect_uris: ["https://client.example/callback#part"],
      },
    ],
    [
      "credentials",
      {
        ...publicClient,
        redirect_uris: ["https://user:pass@client.example/callback"],
      },
    ],
    [
      "non-loopback HTTP",
      { ...publicClient, redirect_uris: ["http://client.example/callback"] },
    ],
    [
      "more than ten URIs",
      {
        ...publicClient,
        redirect_uris: Array.from(
          { length: 11 },
          (_, index) => `https://client.example/callback/${index}`,
        ),
      },
    ],
  ])("rejects %s", async (_reason, client) => {
    const { app } = createTestApp();
    const response = await request(app).post("/register").send(client);

    expect(response.status).toBe(400);
    expect(response.body).toEqual({ error: "invalid_client_metadata" });
  });

  it("rejects request bodies over 32 KiB", async () => {
    const { app } = createTestApp();
    const response = await request(app)
      .post("/register")
      .set("Content-Type", "application/json")
      .send(
        JSON.stringify({ ...publicClient, client_name: "x".repeat(33_000) }),
      );

    expect(response.status).toBe(413);
    expect(response.body).toEqual({ error: "request_too_large" });
  });

  it("rate limits registrations through the durable OAuth store", async () => {
    const { app } = createTestApp();
    const responses = await Promise.all(
      Array.from({ length: 11 }, () =>
        request(app).post("/register").send(publicClient),
      ),
    );

    expect(
      responses.filter((response) => response.status === 201),
    ).toHaveLength(10);
    expect(
      responses.filter((response) => response.status === 429),
    ).toHaveLength(1);
  });

  it("uses one trusted proxy hop to separate client rate-limit buckets", async () => {
    const { app } = createTestApp();
    const firstClient = await Promise.all(
      Array.from({ length: 10 }, () =>
        request(app)
          .post("/register")
          .set("X-Forwarded-For", "198.51.100.11")
          .send(publicClient),
      ),
    );
    const secondClient = await request(app)
      .post("/register")
      .set("X-Forwarded-For", "198.51.100.12")
      .send(publicClient);

    expect(firstClient.every((response) => response.status === 201)).toBe(true);
    expect(secondClient.status).toBe(201);
  });
});
