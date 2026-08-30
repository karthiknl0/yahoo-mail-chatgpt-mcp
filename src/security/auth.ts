import { timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, Response } from 'express';

function constantTimeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function bearerAuth(expectedToken: string) {
  if (expectedToken.length < 32) {
    throw new Error('MCP_API_TOKEN must contain at least 32 characters');
  }

  return (req: Request, res: Response, next: NextFunction): void => {
    const header = req.get('authorization') ?? '';
    const match = /^Bearer\s+(.+)$/i.exec(header);
    if (!match?.[1] || !constantTimeEqual(match[1], expectedToken)) {
      res.setHeader('WWW-Authenticate', 'Bearer');
      res.status(401).json({ error: 'unauthorized' });
      return;
    }
    next();
  };
}
