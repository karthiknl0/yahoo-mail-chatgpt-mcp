import express from 'express';
import request from 'supertest';
import { describe, expect, it } from 'vitest';
import { createOAuthRouter } from '../src/oauth.js';

const TOKEN = 'a'.repeat(32);
const BASE = 'https://mcp.example.com';

function makeApp() {
  const app = express();
  app.use(createOAuthRouter(BASE, TOKEN));
  return app;
}

describe('OAuth 2.0 authorization server', () => {
  it('returns RFC 8414 metadata', async () => {
    const res = await request(makeApp()).get('/.well-known/oauth-authorization-server');
    expect(res.status).toBe(200);
    expect(res.body.issuer).toBe(BASE);
    expect(res.body.authorization_endpoint).toBe(`${BASE}/oauth/authorize`);
    expect(res.body.token_endpoint).toBe(`${BASE}/oauth/token`);
    expect(res.body.code_challenge_methods_supported).toContain('S256');
  });

  it('GET /oauth/authorize returns HTML form', async () => {
    const res = await request(makeApp())
      .get('/oauth/authorize')
      .query({ response_type: 'code', redirect_uri: 'https://chatgpt.com/callback', state: 'xyz' });
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/html');
    expect(res.text).toContain('<form');
    expect(res.text).not.toContain(TOKEN);
  });

  it('POST /oauth/authorize with wrong token returns 401', async () => {
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({ redirect_uri: 'https://chatgpt.com/callback', token: 'wrong' });
    expect(res.status).toBe(401);
    expect(res.text).toContain('Invalid token');
  });

  it('POST /oauth/authorize with correct token redirects with code', async () => {
    const res = await request(makeApp())
      .post('/oauth/authorize')
      .type('form')
      .send({ redirect_uri: 'https://chatgpt.com/callback', token: TOKEN, state: 'abc' });
    expect(res.status).toBe(302);
    const location = res.headers['location'] as string;
    const url = new URL(location);
    expect(url.searchParams.get('code')).toBeTruthy();
    expect(url.searchParams.get('state')).toBe('abc');
  });

  it('POST /oauth/token exchanges code for access_token', async () => {
    const app = makeApp();
    const authRes = await request(app)
      .post('/oauth/authorize')
      .type('form')
      .send({ redirect_uri: 'https://chatgpt.com/callback', token: TOKEN });
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    const tokenRes = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: 'https://chatgpt.com/callback' });
    expect(tokenRes.status).toBe(200);
    expect(tokenRes.body.access_token).toBe(TOKEN);
    expect(tokenRes.body.token_type).toBe('Bearer');
  });

  it('POST /oauth/token rejects a replayed code', async () => {
    const app = makeApp();
    const authRes = await request(app)
      .post('/oauth/authorize')
      .type('form')
      .send({ redirect_uri: 'https://chatgpt.com/callback', token: TOKEN });
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: 'https://chatgpt.com/callback' });

    // Second use of same code must fail.
    const replay = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: 'https://chatgpt.com/callback' });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
  });

  it('POST /oauth/token validates PKCE S256', async () => {
    const { createHash, randomBytes } = await import('node:crypto');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');

    const app = makeApp();
    const authRes = await request(app)
      .post('/oauth/authorize')
      .type('form')
      .send({
        redirect_uri: 'https://chatgpt.com/callback',
        token: TOKEN,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    const code = new URL(authRes.headers['location'] as string).searchParams.get('code')!;

    // Wrong verifier must fail.
    const bad = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code, redirect_uri: 'https://chatgpt.com/callback', code_verifier: 'wrong' });
    expect(bad.status).toBe(400);

    // Code is consumed by the bad attempt, so we need a fresh one.
    const authRes2 = await request(app)
      .post('/oauth/authorize')
      .type('form')
      .send({
        redirect_uri: 'https://chatgpt.com/callback',
        token: TOKEN,
        code_challenge: challenge,
        code_challenge_method: 'S256',
      });
    const code2 = new URL(authRes2.headers['location'] as string).searchParams.get('code')!;

    const good = await request(app)
      .post('/oauth/token')
      .type('form')
      .send({ grant_type: 'authorization_code', code: code2, redirect_uri: 'https://chatgpt.com/callback', code_verifier: verifier });
    expect(good.status).toBe(200);
    expect(good.body.access_token).toBe(TOKEN);
  });
});
