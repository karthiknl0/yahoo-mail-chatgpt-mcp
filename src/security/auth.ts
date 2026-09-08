import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';
import { verifyAccessToken } from './token.js';

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Accepts the master MCP_API_TOKEN (used by the REST API and as break-glass) or a
// signed, expiring token issued through the OAuth flow.
export function bearerAuth(expectedToken: string, tokenEpoch: number) {
  if (expectedToken.length < 32) {
    throw new Error('MCP_API_TOKEN must contain at least 32 characters');
  }

  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.get('authorization') ?? '';
    const match = /^Bearer\s+(.+)$/i.exec(header);
    const presented = match?.[1];

    if (
      presented &&
      (constantTimeEqual(presented, expectedToken) ||
        verifyAccessToken(expectedToken, tokenEpoch, presented) !== null)
    ) {
      next();
      return;
    }

    res.setHeader('WWW-Authenticate', 'Bearer');
    res.status(401).json({ error: 'unauthorized' });
  };
}
