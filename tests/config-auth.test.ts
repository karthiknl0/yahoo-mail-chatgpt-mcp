import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

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

describe("configuration", () => {
  it("fails closed when required secrets are missing", () => {
    expect(() => loadConfig({})).toThrow(
      /Invalid or missing required configuration/,
    );
  });

  it("rejects a public bind without allowed hosts", () => {
    expect(() =>
      loadConfig({ ...validEnv(), HOST: "0.0.0.0", ALLOWED_HOSTS: "" }),
    ).toThrow(/ALLOWED_HOSTS/);
  });

  it.each([
    "REDIS_URL",
    "MCP_LOGIN_PASSPHRASE_SCRYPT",
    "OAUTH_COOKIE_KEY",
  ] as const)("fails closed when %s is missing", (key) => {
    const env = validEnv();
    delete env[key];
    expect(() => loadConfig(env)).toThrow(
      /Invalid or missing required configuration/,
    );
  });

  it("requires a public origin from either explicit or Render configuration", () => {
    const env = validEnv();
    delete env.RENDER_EXTERNAL_URL;
    expect(() => loadConfig(env)).toThrow(
      /PUBLIC_ORIGIN or RENDER_EXTERNAL_URL/,
    );
  });

  it.each([
    "http://yahoo-mail-mcp.onrender.com",
    "https://yahoo-mail-mcp.onrender.com/mcp",
    "https://yahoo-mail-mcp.onrender.com?debug=true",
  ])("rejects an unsafe configured public origin: %s", (origin) => {
    expect(() => loadConfig({ ...validEnv(), PUBLIC_ORIGIN: origin })).toThrow(
      /PUBLIC_ORIGIN/,
    );
  });

  it("prefers explicit PUBLIC_ORIGIN and derives the canonical resource URL", () => {
    const config = loadConfig({
      ...validEnv(),
      PUBLIC_ORIGIN: "https://localhost.example.test",
    });

    expect(config.publicOrigin).toBe("https://localhost.example.test");
    expect(config.resourceUrl).toBe("https://localhost.example.test/mcp");
  });
});
