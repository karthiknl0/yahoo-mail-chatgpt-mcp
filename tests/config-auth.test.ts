import type { NextFunction, Request, Response } from 'express';
import { describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import { bearerAuth } from '../src/security/auth.js';

function validEnv(): NodeJS.ProcessEnv {
  return {
    YAHOO_EMAIL: 'user@example.com',
    YAHOO_APP_PASSWORD: 'app-password-value',
    MCP_API_TOKEN: 'abcdefghijklmnopqrstuvwxyz1234567890',
    HOST: '127.0.0.1',
    ALLOWED_HOSTS: 'localhost,127.0.0.1',
  };
}

describe('configuration', () => {
  it('fails closed when required secrets are missing', () => {
    expect(() => loadConfig({})).toThrow(/Invalid or missing required configuration/);
  });

  it('rejects a public bind without allowed hosts', () => {
    expect(() => loadConfig({ ...validEnv(), HOST: '0.0.0.0', ALLOWED_HOSTS: '' })).toThrow(
      /ALLOWED_HOSTS/,
    );
  });
});

describe('bearer auth', () => {
  it('rejects missing or incorrect credentials', () => {
    const token = validEnv().MCP_API_TOKEN!;
    const middleware = bearerAuth(token);
    const next = vi.fn() as unknown as NextFunction;
    const status = vi.fn().mockReturnThis();
    const json = vi.fn().mockReturnThis();
    const setHeader = vi.fn();
    const res = { status, json, setHeader } as unknown as Response;
    const req = { get: vi.fn().mockReturnValue('Bearer wrong-token') } as unknown as Request;

    middleware(req, res, next);

    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'unauthorized' });
    expect(next).not.toHaveBeenCalled();
  });

  it('accepts the configured bearer token', () => {
    const token = validEnv().MCP_API_TOKEN!;
    const middleware = bearerAuth(token);
    const next = vi.fn() as unknown as NextFunction;
    const res = {} as Response;
    const req = { get: vi.fn().mockReturnValue(`Bearer ${token}`) } as unknown as Request;

    middleware(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });
});
