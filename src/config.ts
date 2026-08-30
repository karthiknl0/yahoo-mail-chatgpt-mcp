import 'dotenv/config';
import { z } from 'zod/v4';

const envSchema = z.object({
  YAHOO_EMAIL: z.string().email(),
  YAHOO_APP_PASSWORD: z.string().min(8),
  MCP_API_TOKEN: z.string().min(32),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default('127.0.0.1'),
  ALLOWED_HOSTS: z.string().default('localhost,127.0.0.1'),
  ALLOWED_ORIGINS: z.string().default(''),
  MAX_EMAILS_PER_REQUEST: z.coerce.number().int().min(1).max(100).default(25),
  MAX_PREVIEW_CHARS: z.coerce.number().int().min(100).max(5000).default(600),
  MAX_READ_CHARS: z.coerce.number().int().min(500).max(20000).default(5000),
  IMAP_CONNECT_TIMEOUT_MS: z.coerce.number().int().min(1000).max(60000).default(15000),
  IMAP_COMMAND_TIMEOUT_MS: z.coerce.number().int().min(1000).max(120000).default(20000),
});

export type AppConfig = ReturnType<typeof loadConfig>;

function splitCsv(value: string): string[] {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const result = envSchema.safeParse(env);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => issue.path.join('.') || 'environment').join(', ');
    throw new Error(`Invalid or missing required configuration: ${issues}`);
  }

  const parsed = result.data;
  const allowedHosts = splitCsv(parsed.ALLOWED_HOSTS);
  if (parsed.HOST === '0.0.0.0' && allowedHosts.length === 0) {
    throw new Error('ALLOWED_HOSTS is required when binding to 0.0.0.0');
  }

  return {
    yahooEmail: parsed.YAHOO_EMAIL,
    yahooAppPassword: parsed.YAHOO_APP_PASSWORD,
    mcpApiToken: parsed.MCP_API_TOKEN,
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
