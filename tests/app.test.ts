import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

function createTestApp() {
  return createApp(
    loadConfig({
      YAHOO_EMAIL: "user@example.com",
      YAHOO_APP_PASSWORD: "app-password-value",
      REDIS_URL: "redis://127.0.0.1:6379",
      PUBLIC_ORIGIN: "https://localhost.example.test",
      MCP_LOGIN_PASSPHRASE_SCRYPT:
        "scrypt$16384$8$1$c2FsdC1mb3ItdGVzdA$3YQqZrjE8xVgkYMi4Z0ddZ6AiBIrrRD5txi1QGcVPTk",
      OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
      HOST: "127.0.0.1",
      ALLOWED_HOSTS: "localhost,127.0.0.1",
    }),
    {
      oauthStore: new InMemoryOAuthStore(),
      createMcpServer: () => {
        throw new Error("MCP server must not be created for a health request");
      },
    },
  );
}

describe("application", () => {
  it("serves only process health data", async () => {
    const response = await request(createTestApp()).get("/health");
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
    expect(JSON.stringify(response.body)).not.toMatch(
      /yahoo|redis|secret|email/i,
    );
  });

  it("rejects unauthenticated MCP requests", async () => {
    const response = await request(createTestApp()).post("/mcp").send({});
    expect(response.status).toBe(401);
    expect(response.body).toEqual({ error: "unauthorized" });
  });
});
