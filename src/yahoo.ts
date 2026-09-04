import { ImapFlow, type FetchMessageObject } from 'imapflow';
import { simpleParser } from 'mailparser';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const pdfParse = require('pdf-parse') as (buf: Buffer) => Promise<{ text: string }>;
import mammoth from 'mammoth';
import * as XLSX from 'xlsx';
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

export interface AttachmentInfo {
  index: number;
  filename: string;
  contentType: string;
  size: number;
  textContent: string | null;
  extractionNote: string | null;
}

function makeClient(config: AppConfig, account?: { email: string; password: string }): ImapFlow {
  return new ImapFlow({
    host: 'imap.mail.yahoo.com',
    port: 993,
    secure: true,
    auth: {
      user: account?.email ?? config.yahooEmail,
      pass: account?.password ?? config.yahooAppPassword,
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

  private async withMailbox<T>(folder: string, fn: (client: ImapFlow) => Promise<T>, account?: { email: string; password: string } | undefined, readOnly = true): Promise<T> {
    const client = makeClient(this.config, account);
    try {
      await client.connect();
      await client.mailboxOpen(folder, { readOnly });
      return await fn(client);
    } finally {
      try {
        await client.logout();
      } catch {
        client.close();
      }
    }
  }

  async listFolders(account?: { email: string; password: string } | undefined): Promise<string[]> {
    const client = makeClient(this.config, account);
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
    account?: { email: string; password: string } | undefined;
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
    }, options.account);
  }

  async readEmail(uid: number, folder = 'INBOX', account?: { email: string; password: string } | undefined): Promise<SafeMailDetail | null> {
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
    }, account);
  }

  async markAsRead(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    const seq = uids.join(',');
    await this.withMailbox(folder, async (client) => {
      await client.messageFlagsAdd(seq, ['\\Seen'], { uid: true });
    }, account, false);
  }

  async markAsUnread(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    const seq = uids.join(',');
    await this.withMailbox(folder, async (client) => {
      await client.messageFlagsRemove(seq, ['\\Seen'], { uid: true });
    }, account, false);
  }

  async flagEmails(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    const seq = uids.join(',');
    await this.withMailbox(folder, async (client) => {
      await client.messageFlagsAdd(seq, ['\\Flagged'], { uid: true });
    }, account, false);
  }

  async unflagEmails(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    const seq = uids.join(',');
    await this.withMailbox(folder, async (client) => {
      await client.messageFlagsRemove(seq, ['\\Flagged'], { uid: true });
    }, account, false);
  }

  async moveEmails(uids: number[], destination: string, folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    const seq = uids.join(',');
    await this.withMailbox(folder, async (client) => {
      await client.messageMove(seq, destination, { uid: true });
    }, account, false);
  }

  async deleteEmails(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    return this.moveEmails(uids, 'Trash', folder, account);
  }

  async archiveEmails(uids: number[], folder = 'INBOX', account?: { email: string; password: string }): Promise<void> {
    return this.moveEmails(uids, 'Archive', folder, account);
  }

  async readEmailAttachments(uid: number, folder = 'INBOX', account?: { email: string; password: string }): Promise<AttachmentInfo[]> {
    return this.withMailbox(folder, async (client) => {
      const message = await client.fetchOne(
        uid,
        { uid: true, source: true },
        { uid: true },
      );
      if (!message || !message.source) return [];

      const parsed = await simpleParser(message.source);
      const results: AttachmentInfo[] = [];

      for (let i = 0; i < parsed.attachments.length; i++) {
        const att = parsed.attachments[i];
        if (!att) continue;
        const filename = att.filename ?? `attachment-${i + 1}`;
        const ct = att.contentType ?? 'application/octet-stream';
        const buf = att.content;
        let textContent: string | null = null;
        let extractionNote: string | null = null;

        try {
          if (ct.startsWith('text/')) {
            textContent = truncateSanitized(buf.toString('utf-8'), this.config.maxReadChars);
          } else if (ct === 'application/pdf' || filename.toLowerCase().endsWith('.pdf')) {
            const data = await pdfParse(buf);
            textContent = truncateSanitized(data.text, this.config.maxReadChars);
          } else if (
            ct === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
            filename.toLowerCase().endsWith('.docx')
          ) {
            const result = await mammoth.extractRawText({ buffer: buf });
            textContent = truncateSanitized(result.value, this.config.maxReadChars);
          } else if (
            ct === 'application/vnd.ms-excel' ||
            ct === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
            filename.toLowerCase().endsWith('.xlsx') ||
            filename.toLowerCase().endsWith('.xls')
          ) {
            const workbook = XLSX.read(buf, { type: 'buffer' });
            const lines: string[] = [];
            for (const sheetName of workbook.SheetNames) {
              const sheet = workbook.Sheets[sheetName];
            const csv = sheet ? XLSX.utils.sheet_to_csv(sheet) : '';
              lines.push(`=== Sheet: ${sheetName} ===\n${csv}`);
            }
            textContent = truncateSanitized(lines.join('\n\n'), this.config.maxReadChars);
          } else {
            extractionNote = `Content type "${ct}" is not supported for text extraction.`;
          }
        } catch (err) {
          extractionNote = `Extraction failed: ${err instanceof Error ? err.message : String(err)}`;
        }

        results.push({ index: i, filename, contentType: ct, size: att.size ?? buf?.length ?? 0, textContent, extractionNote });
      }

      return results;
    }, account);
  }
}
