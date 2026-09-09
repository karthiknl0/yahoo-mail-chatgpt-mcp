import { describe, expect, it, vi } from 'vitest';
import type { AppConfig } from '../src/config.js';
import { getAllAccountsBrief } from '../src/mcp.js';
import type { YahooMailReader } from '../src/yahoo.js';

const config = {
  accounts: [
    { email: 'one@example.com', password: 'not-used' },
    { email: 'two@example.com', password: 'not-used' },
  ],
  maxEmailsPerRequest: 25,
} as unknown as AppConfig;

const mail = {
  uid: 7,
  folder: 'INBOX',
  senderName: 'Bank',
  senderEmail: 'bank@example.com',
  subject: 'Payment receipt',
  receivedAt: '2026-09-09T00:00:00.000Z',
  unread: true,
  hasAttachments: false,
  preview: 'Payment received',
};

describe('getAllAccountsBrief', () => {
  it('returns separate bounded results and preserves account failures', async () => {
    const listEmails = vi
      .fn()
      .mockResolvedValueOnce([mail, { ...mail, uid: 8 }])
      .mockRejectedValueOnce(new Error('upstream failure'));
    const reader = { listEmails } as unknown as YahooMailReader;

    const result = await getAllAccountsBrief(reader, config, { hours: 24, limit: 1, unreadOnly: false });

    expect(result.lookbackHours).toBe(24);
    expect(result.limitPerAccount).toBe(1);
    expect(result.accounts).toEqual([
      expect.objectContaining({ accountNumber: 1, accountEmail: 'one@example.com', status: 'ok', emails: [expect.objectContaining({ uid: 7, category: 'finance' })] }),
      expect.objectContaining({ accountNumber: 2, accountEmail: 'two@example.com', status: 'failed', error: 'fetch_failed', emails: [] }),
    ]);
    expect(listEmails).toHaveBeenCalledTimes(2);
  });
});
