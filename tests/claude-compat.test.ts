import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import type { NextFunction, Request, Response } from 'express';
import request from 'supertest';
import { describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../src/config.js';
import { createYahooMcpServer, formatVoiceBrief } from '../src/mcp.js';
import { createOAuthRouter } from '../src/oauth.js';
import { bearerAuth } from '../src/security/auth.js';
import { issueAccessToken, verifyAccessToken, verifyRefreshToken } from '../src/security/token.js';

const TOKEN = 'a'.repeat(32);
const BASE = 'https://mcp.example.com';
const CLAUDE_REDIRECT = 'https://claude.ai/api/mcp/auth_callback';
const CHATGPT_REDIRECT = 'https://chatgpt.com/connector_platform_oauth_redirect';

function makeApp() {
  const app = express();
  app.use(
    createOAuthRouter(BASE, TOKEN, {
      redirectOrigins: ['https://chatgpt.com', 'https://claude.ai', 'https://claude.com'],
      tokenEpoch: 1,
      accessTokenTtlSeconds: 3600,
    }),
  );
  return app;
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function fullFlow(app: express.Express, redirect: string, clientId?: string) {
  const { verifier, challenge } = pkce();
  const auth = await request(app)
    .post('/oauth/authorize')
    .type('form')
    .send({
      redirect_uri: redirect,
      token: TOKEN,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state: 's1',
      ...(clientId ? { client_id: clientId } : {}),
    });
  expect(auth.status).toBe(302);
  const code = new URL(auth.headers.location as string).searchParams.get('code')!;
  return request(app)
    .post('/oauth/token')
    .type('form')
    .send({
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirect,
      code_verifier: verifier,
      resource: `${BASE}/mcp`,
      ...(clientId ? { client_id: clientId } : {}),
    });
}

describe('ChatGPT flow stays compatible', () => {
  it('authorization_code exchange without registration still returns a working access token', async () => {
    const res = await fullFlow(makeApp(), CHATGPT_REDIRECT);
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.expires_in).toBe(3600);
    expect(verifyAccessToken(TOKEN, 1, res.body.access_token)).not.toBeNull();
  });
});

describe('Claude connector discovery', () => {
  it('advertises registration and refresh support in AS metadata', async () => {
    const res = await request(makeApp()).get('/.well-known/oauth-authorization-server');
    expect(res.body.registration_endpoint).toBe(`${BASE}/register`);
    expect(res.body.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(res.body.code_challenge_methods_supported).toEqual(['S256']);
  });

  it.each(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'])(
    'serves protected resource metadata at %s',
    async (path) => {
      const res = await request(makeApp()).get(path);
      expect(res.status).toBe(200);
      expect(res.body).toEqual({
        resource: `${BASE}/mcp`,
        authorization_servers: [BASE],
        bearer_methods_supported: ['header'],
      });
    },
  );

  it('401 points clients at the resource metadata', () => {
    const middleware = bearerAuth(TOKEN, 1, `${BASE}/.well-known/oauth-protected-resource/mcp`);
    const setHeader = vi.fn();
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn(), setHeader } as unknown as Response;
    middleware({ get: () => undefined } as unknown as Request, res, vi.fn() as unknown as NextFunction);
    expect(setHeader).toHaveBeenCalledWith(
      'WWW-Authenticate',
      `Bearer resource_metadata="${BASE}/.well-known/oauth-protected-resource/mcp"`,
    );
  });
});

describe('dynamic client registration', () => {
  it('registers a public client for the Claude callback', async () => {
    const res = await request(makeApp())
      .post('/register')
      .send({ client_name: 'Claude', redirect_uris: [CLAUDE_REDIRECT], token_endpoint_auth_method: 'none' });
    expect(res.status).toBe(201);
    expect(res.body.client_id).toMatch(/^dcr_/);
    expect(res.body.client_secret).toBeUndefined();
    expect(res.body.token_endpoint_auth_method).toBe('none');
    expect(res.body.redirect_uris).toEqual([CLAUDE_REDIRECT]);
  });

  it('issues a secret when a confidential client method is requested', async () => {
    const res = await request(makeApp())
      .post('/register')
      .send({ redirect_uris: [CLAUDE_REDIRECT], token_endpoint_auth_method: 'client_secret_post' });
    expect(res.status).toBe(201);
    expect(typeof res.body.client_secret).toBe('string');
  });

  it.each([
    [[]],
    [['https://evil.example/cb']],
    [['http://claude.ai/api/mcp/auth_callback']],
    ['not-an-array'],
  ])('rejects invalid redirect_uris %j', async (redirectUris) => {
    const res = await request(makeApp()).post('/register').send({ redirect_uris: redirectUris });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_redirect_uri');
  });

  it('a registered client completes the full flow', async () => {
    const app = makeApp();
    const reg = await request(app).post('/register').send({ redirect_uris: [CLAUDE_REDIRECT] });
    const res = await fullFlow(app, CLAUDE_REDIRECT, reg.body.client_id);
    expect(res.status).toBe(200);
    expect(verifyAccessToken(TOKEN, 1, res.body.access_token)).toEqual({ clientId: reg.body.client_id });
  });
});

describe('refresh tokens', () => {
  it('exchanges a refresh token for a new access token and rotated refresh token', async () => {
    const app = makeApp();
    const first = await fullFlow(app, CLAUDE_REDIRECT, 'client-1');
    expect(typeof first.body.refresh_token).toBe('string');

    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'refresh_token', refresh_token: first.body.refresh_token, client_id: 'client-1' });
    expect(res.status).toBe(200);
    expect(verifyAccessToken(TOKEN, 1, res.body.access_token)).toEqual({ clientId: 'client-1' });
    expect(verifyRefreshToken(TOKEN, 1, res.body.refresh_token)).toEqual({ clientId: 'client-1' });
  });

  it('refresh token is not accepted as a bearer credential', async () => {
    const first = await fullFlow(makeApp(), CLAUDE_REDIRECT);
    expect(verifyAccessToken(TOKEN, 1, first.body.refresh_token)).toBeNull();
  });

  it('access token cannot be used as a refresh token', async () => {
    const { token } = issueAccessToken(TOKEN, 'c', 1, 3600);
    const res = await request(makeApp())
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'refresh_token', refresh_token: token });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });

  it('rejects a refresh token presented by a different client', async () => {
    const app = makeApp();
    const first = await fullFlow(app, CLAUDE_REDIRECT, 'client-1');
    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'refresh_token', refresh_token: first.body.refresh_token, client_id: 'other' });
    expect(res.status).toBe(400);
  });

  it('refresh tokens stop working once the epoch is bumped', async () => {
    const first = await fullFlow(makeApp(), CLAUDE_REDIRECT);
    expect(verifyRefreshToken(TOKEN, 2, first.body.refresh_token)).toBeNull();
  });

  it('rejects a missing or garbage refresh token', async () => {
    for (const refresh_token of [undefined, 'garbage', 'ymcpr1.e30.bad']) {
      const res = await request(makeApp())
        .post('/oauth/token')
        .type('form')
        .send({ grant_type: 'refresh_token', ...(refresh_token ? { refresh_token } : {}) });
      expect(res.status).toBe(400);
    }
  });
});

describe('tool annotations', () => {
  const config = {
    accounts: [{ email: 'one@example.com', password: 'not-used' }],
    maxEmailsPerRequest: 25,
  } as unknown as AppConfig;
  const tools = (
    createYahooMcpServer(config) as unknown as {
      _registeredTools: Record<string, { annotations?: Record<string, unknown> }>;
    }
  )._registeredTools;

  it('annotates every tool', () => {
    for (const [name, tool] of Object.entries(tools)) {
      expect(tool.annotations, name).toBeDefined();
      expect(typeof tool.annotations!.readOnlyHint, name).toBe('boolean');
    }
  });

  it('marks read tools read-only and mailbox changes as writes', () => {
    for (const name of [
      'get_voice_brief',
      'get_all_accounts_morning_brief',
      'get_morning_brief_emails',
      'list_emails',
      'search_emails',
      'read_email',
      'list_folders',
      'read_email_attachments',
    ]) {
      expect(tools[name]!.annotations!.readOnlyHint, name).toBe(true);
    }
    for (const name of ['mark_as_read', 'mark_as_unread', 'flag_emails', 'unflag_emails', 'move_emails', 'archive_emails']) {
      expect(tools[name]!.annotations!.readOnlyHint, name).toBe(false);
    }
    expect(tools.delete_emails!.annotations).toMatchObject({ readOnlyHint: false, destructiveHint: true });
  });
});

describe('formatVoiceBrief', () => {
  it('produces short plain-text lines and reports failed accounts', () => {
    const text = formatVoiceBrief({
      lookbackHours: 24,
      limitPerAccount: 5,
      accounts: [
        {
          accountNumber: 1,
          accountEmail: 'one@example.com',
          status: 'ok',
          emails: [
            {
              uid: 1,
              folder: 'INBOX',
              senderName: 'Bank',
              senderEmail: 'bank@example.com',
              subject: 'Payment receipt',
              receivedAt: '2026-09-09T00:00:00.000Z',
              unread: true,
              hasAttachments: false,
              preview: 'secret preview text',
              category: 'finance',
            },
          ],
        },
        { accountNumber: 2, accountEmail: 'two@example.com', status: 'ok', emails: [] },
        { accountNumber: 3, accountEmail: 'three@example.com', status: 'failed', emails: [], error: 'fetch_failed' },
      ],
    });
    expect(text).toContain('one@example.com: 1 email worth mentioning.');
    expect(text).toContain('1. From Bank: Payment receipt (unread, finance).');
    expect(text).toContain('two@example.com: no new emails in the last 24 hours.');
    expect(text).toContain('three@example.com: could not be checked right now.');
    expect(text).not.toContain('secret preview text');
    expect(text).not.toContain('{');
  });
});
