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
      PUBLIC_ORIGIN: "https://yahoo-mail-mcp.onrender.com",
      MCP_LOGIN_PASSPHRASE_SCRYPT:
        "scrypt$16384$8$1$c2FsdC1mb3ItdGVzdA$3YQqZrjE8xVgkYMi4Z0ddZ6AiBIrrRD5txi1QGcVPTk",
      OAUTH_COOKIE_KEY: "abcdefghijklmnopqrstuvwxyz1234567890ABCDEFG",
      HOST: "127.0.0.1",
      ALLOWED_HOSTS: "localhost,127.0.0.1",
    }),
    {
      oauthStore: new InMemoryOAuthStore(),
      createMcpServer: () => {
        throw new Error("MCP server must not be created for OAuth discovery");
      },
    },
  );
}

describe("OAuth discovery", () => {
  it.each([
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
  ])("serves protected-resource metadata at %s", async (path) => {
    const response = await request(createTestApp()).get(path);

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body.resource).toBe(
      "https://yahoo-mail-mcp.onrender.com/mcp",
    );
    expect(response.body.authorization_servers).toEqual([
      "https://yahoo-mail-mcp.onrender.com",
    ]);
    expect(response.body.bearer_methods_supported).toEqual(["header"]);
  });

  it("serves authorization-server metadata with public PKCE endpoints", async () => {
    const response = await request(createTestApp()).get(
      "/.well-known/oauth-authorization-server",
    );

    expect(response.status).toBe(200);
    expect(response.headers["cache-control"]).toBe("no-store");
    expect(response.body).toMatchObject({
      issuer: "https://yahoo-mail-mcp.onrender.com",
      authorization_endpoint: "https://yahoo-mail-mcp.onrender.com/authorize",
      token_endpoint: "https://yahoo-mail-mcp.onrender.com/token",
      registration_endpoint: "https://yahoo-mail-mcp.onrender.com/register",
      code_challenge_methods_supported: ["S256"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });
});
