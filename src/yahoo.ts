import { ImapFlow, type FetchMessageObject } from 'imapflow';
import { simpleParser } from 'mailparser';
import type { AppConfig } from './config.js';
import { sanitizeHeader, truncateSanitized } from './security/redact.js';

export interface SafeMailSummary {
  uid: number;
  folder: string;
  senderName: string;
  senderEmail: string;
  subject: string;
  receivedAt: string | null;
  unread: boolean;
  hasAttachments: boolean;
  preview: string;
}

export interface SafeMailDetail extends SafeMailSummary {
  body: string;
}

function makeClient(config: AppConfig): ImapFlow {
  return new ImapFlow({
    host: 'imap.mail.yahoo.com',
    port: 993,
    secure: true,
    auth: {
      user: config.yahooEmail,
      pass: config.yahooAppPassword,
    },
    logger: false,
    tls: {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    },
    connectionTimeout: config.imapConnectTimeoutMs,
    greetingTimeout: config.imapConnectTimeoutMs,
    socketTimeout: config.imapCommandTimeoutMs,
  });
}

function firstAddress(message: FetchMessageObject): { name: string; address: string } {
  const first = message.envelope?.from?.[0];
  return {
    name: first?.name ?? '',
    address: first?.address ?? '',
  };
}

function toIsoDate(value: string | Date | undefined): string | null {
  if (!value) return null;
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

async function toSummary(
  message: FetchMessageObject,
  folder: string,
  maxPreviewChars: number,
  preParsed?: Awaited<ReturnType<typeof simpleParser>>,
): Promise<SafeMailSummary> {
  const parsed = preParsed ?? (message.source ? await simpleParser(message.source) : undefined);
  const sender = firstAddress(message);
  const text = parsed?.text ?? parsed?.html?.toString() ?? '';

  return {
    uid: message.uid,
    folder,
    senderName: sanitizeHeader(sender.name),
    senderEmail: sender.address,
    subject: sanitizeHeader(message.envelope?.subject ?? '(no subject)'),
    receivedAt: toIsoDate(message.internalDate ?? message.envelope?.date),
    unread: !message.flags?.has('\\Seen'),
    hasAttachments: (parsed?.attachments.length ?? 0) > 0,
    preview: truncateSanitized(text, maxPreviewChars),
  };
}

export class YahooMailReader {
  constructor(private readonly config: AppConfig) {}

  private async withMailbox<T>(folder: string, fn: (client: ImapFlow) => Promise<T>): Promise<T> {
    const client = makeClient(this.config);
    try {
      await client.connect();
      await client.mailboxOpen(folder, { readOnly: true });
      return await fn(client);
    } finally {
      try {
        await client.logout();
      } catch {
        client.close();
      }
    }
  }

  async listFolders(): Promise<string[]> {
    const client = makeClient(this.config);
    try {
      await client.connect();
      const folders = await client.list();
      return folders.map((folder) => folder.path).slice(0, 100);
    } finally {
      try {
        await client.logout();
      } catch {
        client.close();
      }
    }
  }

  async listEmails(options: {
    folder?: string;
    limit?: number;
    unreadOnly?: boolean;
    since?: Date;
    query?: string;
  }): Promise<SafeMailSummary[]> {
    const folder = options.folder ?? 'INBOX';
    const limit = Math.min(options.limit ?? 10, this.config.maxEmailsPerRequest);

    return this.withMailbox(folder, async (client) => {
      const criteria: Record<string, unknown> = {};
      if (options.unreadOnly) criteria.seen = false;
      if (options.since) criteria.since = options.since;
      if (options.query) criteria.text = options.query;

      const searchResult = await client.search(criteria, { uid: true });
      const uids = Array.isArray(searchResult) ? searchResult : [];
      const selected = uids.slice(-limit).reverse();
      const results: SafeMailSummary[] = [];

      for (const uid of selected) {
        const message = await client.fetchOne(
          uid,
          { uid: true, envelope: true, flags: true, internalDate: true, source: true },
          { uid: true },
        );
        if (message) results.push(await toSummary(message, folder, this.config.maxPreviewChars));
      }

      return results;
    });
  }

  async readEmail(uid: number, folder = 'INBOX'): Promise<SafeMailDetail | null> {
    return this.withMailbox(folder, async (client) => {
      const message = await client.fetchOne(
        uid,
        { uid: true, envelope: true, flags: true, internalDate: true, source: true },
        { uid: true },
      );
      if (!message) return null;

      const parsed = message.source ? await simpleParser(message.source) : undefined;
      const summary = await toSummary(message, folder, this.config.maxPreviewChars, parsed);
      const text = parsed?.text ?? parsed?.html?.toString() ?? '';
      return {
        ...summary,
        body: truncateSanitized(text, this.config.maxReadChars),
      };
    });
  }
}
