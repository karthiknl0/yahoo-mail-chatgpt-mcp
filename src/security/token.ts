import { createHmac, timingSafeEqual } from 'node:crypto';

// Access tokens are stateless: an HMAC over the payload lets them survive container
// restarts without storage. Revocation is by bumping TOKEN_EPOCH, which invalidates
// every previously issued token without rotating MCP_API_TOKEN.

interface TokenPayload {
  c: string; // client id
  e: number; // token epoch
  x: number; // expiry, unix seconds
}

const PREFIX = 'ymcp1';

function signingKey(masterSecret: string): Buffer {
  return createHmac('sha256', masterSecret).update('mcp-access-token-v1').digest();
}

function sign(key: Buffer, body: string): string {
  return createHmac('sha256', key).update(body).digest('base64url');
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

export function issueAccessToken(
  masterSecret: string,
  clientId: string,
  epoch: number,
  ttlSeconds: number,
): { token: string; expiresIn: number } {
  const payload: TokenPayload = {
    c: clientId.slice(0, 100),
    e: epoch,
    x: Math.floor(Date.now() / 1000) + ttlSeconds,
  };
  const body = `${PREFIX}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return { token: `${body}.${sign(signingKey(masterSecret), body)}`, expiresIn: ttlSeconds };
}

export function verifyAccessToken(
  masterSecret: string,
  epoch: number,
  token: string,
): { clientId: string } | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== PREFIX) return null;
  const [, encoded, signature] = parts;
  if (!encoded || !signature) return null;

  if (!safeEqual(signature, sign(signingKey(masterSecret), `${PREFIX}.${encoded}`))) return null;

  let payload: TokenPayload;
  try {
    payload = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf-8')) as TokenPayload;
  } catch {
    return null;
  }

  if (typeof payload.x !== 'number' || payload.x < Math.floor(Date.now() / 1000)) return null;
  if (payload.e !== epoch) return null;
  if (typeof payload.c !== 'string') return null;

  return { clientId: payload.c };
}
