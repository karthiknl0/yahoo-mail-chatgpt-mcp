import { scryptSync } from "node:crypto";
import {
  LATEST_PROTOCOL_VERSION,
  McpServer,
} from "@modelcontextprotocol/server";
import request from "supertest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { z } from "zod/v4";
import { createApp } from "../src/app.js";
import { loadConfig } from "../src/config.js";
import { pkceChallenge } from "../src/oauth/crypto.js";
import { InMemoryOAuthStore } from "./helpers/in-memory-oauth-store.js";

const origin = "https://yahoo-mail-mcp.onrender.com";
const resource = `${origin}/mcp`;
const redirectUri = "https://chatgpt.com/connector_platform_oauth_redirect";
const passphrase = "owner-only integration passphrase";
const verifier = "mcp-inspector-verifier-value-1234567890-abcdef";
const oauthState = "inspector-state-value";
const yahooEmail = "owner-oauth-flow@example.test";
const mailboxValues = {
  sender: "Synthetic Sender Sentinel",
  subject: "Synthetic Subject Sentinel",
  body: "Synthetic Body Sentinel",
  folder: "Synthetic Folder Sentinel",
};
const toolNames = [
  "get_morning_brief_emails",
  "list_emails",
  "search_emails",
  "read_email",
  "list_folders",
] as const;

const salt = Buffer.from("oauth-flow-test-salt");
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

function createToolServer(): McpServer {
  const server = new McpServer({
    name: "yahoo-mail-chatgpt-mcp-test",
    version: "0.1.0",
  });
  for (const name of toolNames) {
    server.registerTool(
      name,
      {
        description: "Read-only test tool; it never opens a mailbox.",
        inputSchema: z.object({}),
      },
      async () => ({
        content: [{ type: "text", text: JSON.stringify({ ok: true }) }],
      }),
    );
  }
  return server;
}

function createTestApp(store = new InMemoryOAuthStore()) {
  const config = loadConfig({
    YAHOO_EMAIL: yahooEmail,
    YAHOO_APP_PASSWORD: "synthetic-yahoo-app-password",
    REDIS_URL: "redis://oauth-flow.test.invalid:6379",
    PUBLIC_ORIGIN: origin,
    MCP_LOGIN_PASSPHRASE_SCRYPT: passphraseDigest,
    OAUTH_COOKIE_KEY: "oauth-flow-cookie-key-32-bytes-minimum-value",
    HOST: "127.0.0.1",
    ALLOWED_HOSTS: "localhost,127.0.0.1",
  });
  return {
    app: createApp(config, {
      oauthStore: store,
      createMcpServer: createToolServer,
    }),
    store,
  };
}

function hiddenValue(html: string, name: string): string {
  const value = new RegExp(`name="${name}" value="([^"]+)"`).exec(html)?.[1];
  expect(value).toEqual(expect.any(String));
  return value!;
}

async function mcpRequest(
  app: ReturnType<typeof createTestApp>["app"],
  accessToken: string,
  id: number,
  method: string,
  params: Record<string, unknown>,
) {
  return request(app)
    .post("/mcp")
    .set("Authorization", `Bearer ${accessToken}`)
    .set("Accept", "application/json, text/event-stream")
    .send({ jsonrpc: "2.0", id, method, params });
}

interface McpMessage {
  readonly result?: {
    readonly protocolVersion?: string;
    readonly serverInfo?: { readonly name?: string; readonly version?: string };
    readonly tools?: readonly { readonly name: string }[];
  };
}

function mcpMessage(response: request.Response): McpMessage {
  if (response.type === "application/json") {
    return response.body as McpMessage;
  }
  const data = response.text
    .split("\n")
    .find((line) => line.startsWith("data: "))
    ?.slice("data: ".length);
  expect(data).toEqual(expect.any(String));
  return JSON.parse(data!) as McpMessage;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("complete in-memory OAuth protocol flow", () => {
  it("reaches exactly five read-only tools and rotates old credentials without leaking sensitive values", async () => {
    const capturedErrors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...values: unknown[]) => {
      capturedErrors.push(values.map((value) => String(value)).join(" "));
    });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const { app } = createTestApp();

    const registration = await request(app)
      .post("/register")
      .send({
        redirect_uris: [redirectUri],
        client_name: "MCP Inspector integration test",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
        scope: "mcp:read",
      });
    expect(registration.status).toBe(201);
    const clientId = registration.body.client_id as string;
    expect(clientId).toEqual(expect.any(String));

    const challenge = await pkceChallenge(verifier);
    const authorization = await request(app).get("/authorize").query({
      response_type: "code",
      client_id: clientId,
      redirect_uri: redirectUri,
      resource,
      state: oauthState,
      code_challenge: challenge,
      code_challenge_method: "S256",
      scope: "mcp:read",
    });
    expect(authorization.status).toBe(200);
    const cookie = authorization.headers["set-cookie"]?.[0]?.split(";", 1)[0];
    expect(cookie).toEqual(expect.any(String));
    const transactionId = hiddenValue(authorization.text, "transaction_id");
    const csrf = hiddenValue(authorization.text, "csrf");

    const decision = await request(app)
      .post("/authorize")
      .set("Cookie", cookie!)
      .type("form")
      .send({
        transaction_id: transactionId,
        csrf,
        decision: "allow",
        passphrase,
      });
    expect(decision.status).toBe(302);
    const redirect = new URL(decision.headers.location!);
    expect(redirect.origin + redirect.pathname).toBe(redirectUri);
    expect(redirect.searchParams.get("state")).toBe(oauthState);
    const code = redirect.searchParams.get("code");
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const tokenExchange = await request(app).post("/token").type("form").send({
      grant_type: "authorization_code",
      code,
      client_id: clientId,
      redirect_uri: redirectUri,
      resource,
      code_verifier: verifier,
    });
    expect(tokenExchange.status).toBe(200);
    const accessToken = tokenExchange.body.access_token as string;
    const refreshToken = tokenExchange.body.refresh_token as string;

    const initialized = await mcpRequest(app, accessToken, 1, "initialize", {
      protocolVersion: LATEST_PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name: "oauth-flow-test", version: "0.1.0" },
    });
    expect(initialized.status).toBe(200);
    expect(mcpMessage(initialized).result).toMatchObject({
      protocolVersion: LATEST_PROTOCOL_VERSION,
      serverInfo: { name: "yahoo-mail-chatgpt-mcp-test", version: "0.1.0" },
    });

    const tools = await mcpRequest(app, accessToken, 2, "tools/list", {});
    expect(tools.status).toBe(200);
    const toolsMessage = mcpMessage(tools);
    expect(toolsMessage.result?.tools?.map((tool) => tool.name)).toEqual(
      toolNames,
    );
    expect(JSON.stringify(toolsMessage)).not.toContain(yahooEmail);
    for (const value of Object.values(mailboxValues)) {
      expect(JSON.stringify(toolsMessage)).not.toContain(value);
    }

    const rotation = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      resource,
    });
    expect(rotation.status).toBe(200);
    const rotatedAccessToken = rotation.body.access_token as string;
    const rotatedRefreshToken = rotation.body.refresh_token as string;
    expect(rotatedAccessToken).not.toBe(accessToken);
    expect(rotatedRefreshToken).not.toBe(refreshToken);

    const rotatedTools = await mcpRequest(
      app,
      rotatedAccessToken,
      3,
      "tools/list",
      {},
    );
    expect(rotatedTools.status).toBe(200);

    const oldAccess = await mcpRequest(app, accessToken, 4, "tools/list", {});
    expect(oldAccess.status).toBe(401);
    expect(oldAccess.body).toEqual({ error: "unauthorized" });

    const oldRefresh = await request(app).post("/token").type("form").send({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: clientId,
      resource,
    });
    expect(oldRefresh.status).toBe(400);
    expect(oldRefresh.body).toEqual({ error: "invalid_grant" });

    const newestRefreshAfterReplay = await request(app)
      .post("/token")
      .type("form")
      .send({
        grant_type: "refresh_token",
        refresh_token: rotatedRefreshToken,
        client_id: clientId,
        resource,
      });
    expect(newestRefreshAfterReplay.status).toBe(400);
    expect(newestRefreshAfterReplay.body).toEqual({ error: "invalid_grant" });

    const failedAccessToken = "F".repeat(43);
    class FailingAccessStore extends InMemoryOAuthStore {
      override async getAccessToken(): Promise<never> {
        throw new Error(
          [
            passphrase,
            code,
            verifier,
            accessToken,
            refreshToken,
            rotatedAccessToken,
            rotatedRefreshToken,
            yahooEmail,
            ...Object.values(mailboxValues),
          ].join(" "),
        );
      }
    }
    const failedFlow = await mcpRequest(
      createTestApp(new FailingAccessStore()).app,
      failedAccessToken,
      5,
      "tools/list",
      {},
    );
    expect(failedFlow.status).toBe(500);
    expect(failedFlow.body).toEqual({ error: "internal_error" });
    expect(capturedErrors).toEqual(["Request failed Error"]);

    const logs = capturedErrors.join("\n");
    for (const value of [
      passphrase,
      code!,
      verifier,
      accessToken,
      refreshToken,
      rotatedAccessToken,
      rotatedRefreshToken,
      failedAccessToken,
      yahooEmail,
      ...Object.values(mailboxValues),
    ]) {
      expect(logs).not.toContain(value);
    }
  });
});
