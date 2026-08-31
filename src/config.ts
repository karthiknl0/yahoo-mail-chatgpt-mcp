import "dotenv/config";
import { z } from "zod/v4";

const envSchema = z.object({
  YAHOO_EMAIL: z.string().email(),
  YAHOO_APP_PASSWORD: z.string().min(8),
  REDIS_URL: z.string().url(),
  PUBLIC_ORIGIN: z.string().url().optional(),
  RENDER_EXTERNAL_URL: z.string().url().optional(),
  MCP_LOGIN_PASSPHRASE_SCRYPT: z
    .string()
    .regex(/^scrypt\$16384\$8\$1\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/),
  OAUTH_COOKIE_KEY: z.string().min(32),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default("127.0.0.1"),
  ALLOWED_HOSTS: z.string().default("localhost,127.0.0.1"),
  ALLOWED_ORIGINS: z.string().default(""),
  MAX_EMAILS_PER_REQUEST: z.coerce.number().int().min(1).max(100).default(25),
  MAX_PREVIEW_CHARS: z.coerce.number().int().min(100).max(5000).default(600),
  MAX_READ_CHARS: z.coerce.number().int().min(500).max(20000).default(5000),
  IMAP_CONNECT_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(60000)
    .default(15000),
  IMAP_COMMAND_TIMEOUT_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(120000)
    .default(20000),
});

export type AppConfig = ReturnType<typeof loadConfig>;

function splitCsv(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizePublicOrigin(
  origin: string,
  field: "PUBLIC_ORIGIN" | "RENDER_EXTERNAL_URL",
): string {
  const url = new URL(origin);
  if (
    url.protocol !== "https:" ||
    url.pathname !== "/" ||
    url.search !== "" ||
    url.username !== "" ||
    url.password !== "" ||
    url.hash !== ""
  ) {
    throw new Error(
      `${field} must be an HTTPS origin without a path, query, credentials, or fragment`,
    );
  }
  return url.origin;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => issue.path.join(".") || "environment")
      .join(", ");
    throw new Error(`Invalid or missing required configuration: ${issues}`);
  }

  const parsed = result.data;
  const originField = parsed.PUBLIC_ORIGIN
    ? "PUBLIC_ORIGIN"
    : "RENDER_EXTERNAL_URL";
  const rawPublicOrigin = parsed.PUBLIC_ORIGIN ?? parsed.RENDER_EXTERNAL_URL;
  if (!rawPublicOrigin) {
    throw new Error("PUBLIC_ORIGIN or RENDER_EXTERNAL_URL is required");
  }
  const publicOrigin = normalizePublicOrigin(rawPublicOrigin, originField);
  const allowedHosts = splitCsv(parsed.ALLOWED_HOSTS);
  if (parsed.HOST === "0.0.0.0" && allowedHosts.length === 0) {
    throw new Error("ALLOWED_HOSTS is required when binding to 0.0.0.0");
  }

  return {
    yahooEmail: parsed.YAHOO_EMAIL,
    yahooAppPassword: parsed.YAHOO_APP_PASSWORD,
    redisUrl: parsed.REDIS_URL,
    publicOrigin,
    resourceUrl: new URL("/mcp", publicOrigin).toString(),
    passphraseDigest: parsed.MCP_LOGIN_PASSPHRASE_SCRYPT,
    oauthCookieKey: parsed.OAUTH_COOKIE_KEY,
    port: parsed.PORT,
    host: parsed.HOST,
    allowedHosts,
    allowedOrigins: splitCsv(parsed.ALLOWED_ORIGINS),
    maxEmailsPerRequest: parsed.MAX_EMAILS_PER_REQUEST,
    maxPreviewChars: parsed.MAX_PREVIEW_CHARS,
    maxReadChars: parsed.MAX_READ_CHARS,
    imapConnectTimeoutMs: parsed.IMAP_CONNECT_TIMEOUT_MS,
    imapCommandTimeoutMs: parsed.IMAP_COMMAND_TIMEOUT_MS,
  } as const;
}
