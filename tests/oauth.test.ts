import { createHash, randomBytes } from 'node:crypto';
import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createOAuthRouter } from '../src/oauth.js';
import { verifyAccessToken } from '../src/security/token.js';

const TOKEN = 'a'.repeat(32);
const BASE = 'https://mcp.example.com';
const REDIRECT = 'https://chatgpt.com/connector/oauth/abc123';
const EPOCH = 1;

function makeApp() {
  const app = express();
  app.use(
    createOAuthRouter(BASE, TOKEN, {
      redirectOrigins: ['https://chatgpt.com', 'https://claude.ai'],
      tokenEpoch: EPOCH,
      accessTokenTtlSeconds: 3600,
    }),
  );
  return app;
}

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

async function authorize(app: express.Express, challenge: string, extra: Record<string, string> = {}) {
  return request(app)
    .post('/oauth/authorize')
    .type('form')
    .send({
      redirect_uri: REDIRECT,
      token: TOKEN,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      ...extra,
    });
}

describe('OAuth 2.0 authorization server', () => {
  it('returns RFC 8414 metadata advertising only S256', async () => {
    const res = await request(makeApp()).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(BASE);
    expect(res.body.authorization_endpoint).toBe(`${BASE}/oauth/authorize`);
    expect(res.body.code_challenge_methods_supported).toEqual(['S256']);
  });

  it('GET /oauth/authorize returns HTML form for an allowed redirect', async () => {
    const { challenge } = pkce();
    const res = await request(makeApp()).get('/oauth/authorize').query({
      response_type: 'code',
      redirect_uri: REDIRECT,
      state: 'xyz',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(200);
    expect(res.text).toContain('<form');
    expect(res.text).not.toContain(TOKEN);
  });

  it('rejects a redirect_uri outside the allowlist', async () => {
    const { challenge } = pkce();
    const res = await request(makeApp()).get('/oauth/authorize').query({
      response_type: 'code',
      redirect_uri: 'https://evil.example/steal',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
    expect(res.body.error_description).toContain('redirect_uri');
  });

  it('rejects a non-https redirect_uri on an allowed host', async () => {
    const { challenge } = pkce();
    const res = await request(makeApp()).get('/oauth/authorize').query({
      response_type: 'code',
      redirect_uri: 'http://chatgpt.com/connector/oauth/abc',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    expect(res.status).toBe(400);
  });

  it('rejects a disallowed redirect_uri posted directly, bypassing the GET form', async () => {
    const { challenge } = pkce();
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({
        redirect_uri: 'https://evil.example/steal',
        token: TOKEN,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    expect(res.status).toBe(400);
    expect(res.headers['location']).toBeUndefined();
  });

  it('requires PKCE S256 — a request without a challenge is refused', async () => {
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({ redirect_uri: REDIRECT, token: TOKEN });
    expect(res.status).toBe(400);
    expect(res.body.error_description).toContain('PKCE');
  });

  it('refuses the downgraded "plain" challenge method', async () => {
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({
        redirect_uri: REDIRECT,
        token: TOKEN,
        code_challenge: 'somechallenge',
        code_challenge_method: 'plain',
      });
    expect(res.status).toBe(400);
  });

  it('POST /oauth/authorize with wrong token returns 401', async () => {
    const { challenge } = pkce();
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({
        redirect_uri: REDIRECT,
        token: 'wrong',
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid token');
  });

  it('issues a signed token that is NOT the master secret', async () => {
    const app = makeApp();
    const { verifier, challenge } = pkce();
    const authRes = await authorize(app, challenge, { client_id: 'chatgpt' });
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier });

    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe('Bearer');
    expect(res.body.access_token).not.toBe(TOKEN);
    expect(res.body.expires_in).toBe(3600);

    const verified = verifyAccessToken(TOKEN, EPOCH, res.body.access_token as string);
    expect(verified?.clientId).toBe('chatgpt');
  });

  it('an issued token stops verifying once the epoch is bumped', async () => {
    const app = makeApp();
    const { verifier, challenge } = pkce();
    const authRes = await authorize(app, challenge);
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;
    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier });

    const token = res.body.access_token as string;
    expect(verifyAccessToken(TOKEN, EPOCH, token)).not.toBeNull();
    expect(verifyAccessToken(TOKEN, EPOCH + 1, token)).toBeNull();
  });

  it('POST /oauth/token rejects a replayed code', async () => {
    const app = makeApp();
    const { verifier, challenge } = pkce();
    const authRes = await authorize(app, challenge);
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;
    const body = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier };

    await request(app).post('/oauth/token').type('form').send(body);
    const replay = await request(app).post('/oauth/token').type('form').send(body);

    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
  });

  it('POST /oauth/token rejects a wrong PKCE verifier', async () => {
    const app = makeApp();
    const { challenge } = pkce();
    const authRes = await authorize(app, challenge);
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: 'wrong' });
    expect(res.status).toBe(400);
  });

  it('POST /oauth/token rejects a mismatched redirect_uri', async () => {
    const app = makeApp();
    const { verifier, challenge } = pkce();
    const authRes = await authorize(app, challenge);
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    const res = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({
        grant_type: 'authorization_code',
        code,
        redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
        code_verifier: verifier,
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('invalid_grant');
  });
});
