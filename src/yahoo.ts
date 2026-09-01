import { ImapFlow, type FetchMessageObject } from "imapflow";
import { simpleParser } from "mailparser";
import type { AppConfig } from "./config.js";
import {
  truncateMailDisplayText,
  truncateSanitized,
} from "./security/redact.js";

const MAX_MAIL_DISPLAY_CHARS = 200;

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
    host: "imap.mail.yahoo.com",
    port: 993,
    secure: true,
    auth: {
      user: config.yahooEmail,
      pass: config.yahooAppPassword,
    },
    logger: false,
    tls: {
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
    },
    connectionTimeout: config.imapConnectTimeoutMs,
    greetingTimeout: config.imapConnectTimeoutMs,
    socketTimeout: config.imapCommandTimeoutMs,
  });
}

function firstAddress(message: FetchMessageObject): {
  name: string;
  address: string;
} {
  const first = message.envelope?.from?.[0];
  return {
    name: first?.name ?? "",
    address: first?.address ?? "",
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
  signal: AbortSignal,
): Promise<SafeMailSummary> {
  const parsed = await parseMail(message, signal);
  const sender = firstAddress(message);
  const text = parsed?.text ?? parsed?.html?.toString() ?? "";

  throwIfAborted(signal);
  return {
    uid: message.uid,
    folder: truncateMailDisplayText(folder, MAX_MAIL_DISPLAY_CHARS),
    senderName: truncateMailDisplayText(sender.name, MAX_MAIL_DISPLAY_CHARS),
    senderEmail: truncateMailDisplayText(
      sender.address,
      MAX_MAIL_DISPLAY_CHARS,
    ),
    subject: truncateMailDisplayText(
      message.envelope?.subject ?? "(no subject)",
      MAX_MAIL_DISPLAY_CHARS,
    ),
    receivedAt: toIsoDate(message.internalDate ?? message.envelope?.date),
    unread: !message.flags?.has("\\Seen"),
    hasAttachments: (parsed?.attachments.length ?? 0) > 0,
    preview: truncateSanitized(text, maxPreviewChars),
  };
}

function abortError(signal: AbortSignal): Error {
  const reason = signal.reason;
  if (reason instanceof Error) return reason;
  const error = new Error("Yahoo Mail request aborted");
  error.name = "AbortError";
  return error;
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw abortError(signal);
}

async function awaitAbortable<T>(
  operation: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  throwIfAborted(signal);
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(abortError(signal));
    signal.addEventListener("abort", onAbort, { once: true });
    operation
      .then((value) => {
        if (signal.aborted) reject(abortError(signal));
        else resolve(value);
      }, reject)
      .finally(() => {
        signal.removeEventListener("abort", onAbort);
      });
  });
}

async function parseMail(message: FetchMessageObject, signal: AbortSignal) {
  if (!message.source) return undefined;
  const parsed = await awaitAbortable(simpleParser(message.source), signal);
  throwIfAborted(signal);
  return parsed;
}

export class YahooMailReader {
  constructor(private readonly config: AppConfig) {}

  private async withMailbox<T>(
    folder: string,
    fn: (client: ImapFlow, signal: AbortSignal) => Promise<T>,
    signal?: AbortSignal,
  ): Promise<T> {
    return this.withClient(async (client, operationSignal) => {
      await awaitAbortable(client.connect(), operationSignal);
      await awaitAbortable(
        client.mailboxOpen(folder, { readOnly: true }),
        operationSignal,
      );
      return fn(client, operationSignal);
    }, signal);
  }

  private async withClient<T>(
    fn: (client: ImapFlow, signal: AbortSignal) => Promise<T>,
    requestSignal?: AbortSignal,
  ): Promise<T> {
    const client = makeClient(this.config);
    const operation = new AbortController();
    const abortForRequest = () => operation.abort(requestSignal?.reason);
    if (requestSignal?.aborted) {
      abortForRequest();
    } else {
      requestSignal?.addEventListener("abort", abortForRequest, {
        once: true,
      });
    }
    const timeoutMs = Math.min(
      120_000,
      Math.max(
        1_000,
        this.config.imapConnectTimeoutMs + this.config.imapCommandTimeoutMs,
      ),
    );
    const timeout = setTimeout(
      () => operation.abort(new Error("Yahoo Mail request timed out")),
      timeoutMs,
    );
    const signal = operation.signal;
    const closeOnAbort = () => client.close();
    signal.addEventListener("abort", closeOnAbort, { once: true });
    try {
      throwIfAborted(signal);
      return await fn(client, signal);
    } finally {
      clearTimeout(timeout);
      requestSignal?.removeEventListener("abort", abortForRequest);
      signal.removeEventListener("abort", closeOnAbort);
      if (signal.aborted) {
        client.close();
      } else {
        try {
          await client.logout();
        } catch {
          client.close();
        }
      }
    }
  }

  async listFolders(options: { signal?: AbortSignal } = {}): Promise<string[]> {
    return this.withClient(async (client, signal) => {
      await awaitAbortable(client.connect(), signal);
      const folders = await awaitAbortable(client.list(), signal);
      return folders
        .map((folder) =>
          truncateMailDisplayText(folder.path, MAX_MAIL_DISPLAY_CHARS),
        )
        .slice(0, 100);
    }, options.signal);
  }

  async listEmails(options: {
    folder?: string;
    limit?: number;
    unreadOnly?: boolean;
    since?: Date;
    query?: string;
    signal?: AbortSignal;
  }): Promise<SafeMailSummary[]> {
    const folder = options.folder ?? "INBOX";
    const limit = Math.min(
      options.limit ?? 10,
      this.config.maxEmailsPerRequest,
    );

    return this.withMailbox(
      folder,
      async (client, signal) => {
        const criteria: Record<string, unknown> = {};
        if (options.unreadOnly) criteria.seen = false;
        if (options.since) criteria.since = options.since;
        if (options.query) criteria.text = options.query;

        const searchResult = await awaitAbortable(
          client.search(criteria, { uid: true }),
          signal,
        );
        const uids = Array.isArray(searchResult) ? searchResult : [];
        const selected = uids.slice(-limit).reverse();
        const results: SafeMailSummary[] = [];

        for (const uid of selected) {
          const message = await awaitAbortable(
            client.fetchOne(
              uid,
              {
                uid: true,
                envelope: true,
                flags: true,
                internalDate: true,
                source: true,
              },
              { uid: true },
            ),
            signal,
          );
          if (message)
            results.push(
              await toSummary(
                message,
                folder,
                this.config.maxPreviewChars,
                signal,
              ),
            );
        }

        return results;
      },
      options.signal,
    );
  }

  async readEmail(
    uid: number,
    folder = "INBOX",
    options: { signal?: AbortSignal } = {},
  ): Promise<SafeMailDetail | null> {
    return this.withMailbox(
      folder,
      async (client, signal) => {
        const message = await awaitAbortable(
          client.fetchOne(
            uid,
            {
              uid: true,
              envelope: true,
              flags: true,
              internalDate: true,
              source: true,
            },
            { uid: true },
          ),
          signal,
        );
        if (!message) return null;

        const summary = await toSummary(
          message,
          folder,
          this.config.maxPreviewChars,
          signal,
        );
        const parsed = await parseMail(message, signal);
        const text = parsed?.text ?? parsed?.html?.toString() ?? "";
        throwIfAborted(signal);
        return {
          ...summary,
          body: truncateSanitized(text, this.config.maxReadChars),
        };
      },
      options.signal,
    );
  }
}
