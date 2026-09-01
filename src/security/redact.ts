const REDACTED = "[REDACTED]";

const authKeywordPattern =
  /\b(?:otp|one[- ]?time(?: password| passcode)?|verification|verify|security|login|authentication|auth|passcode|pin|code)\b/i;

const sensitiveUrlKeywordPattern =
  /(?:reset|recover|recovery|verify|verification|authenticate|authentication|authorize|authorization|login|signin|magic|token|otp|code|password)/i;

const urlPattern = /https?:\/\/[^\s<>"']+/gi;
const longDigitPattern = /\b(?:\d[ -]?){12,19}\b/g;
const contextualCodePattern = /\b\d(?:[\s.-]?\d){3,7}\b/g;
const bearerLikePattern =
  /\b(?:bearer\s+)?[A-Za-z0-9_-]{24,}\.[A-Za-z0-9._-]{8,}\b/gi;

function normalizeCode(candidate: string): string {
  return candidate.replace(/[^0-9]/g, "");
}

export function stripHtml(input: string): string {
  return input
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

function redactSensitiveUrls(text: string): string {
  return text.replace(urlPattern, (url) => {
    try {
      const parsed = new URL(url);
      const sensitive =
        sensitiveUrlKeywordPattern.test(parsed.pathname) ||
        [...parsed.searchParams.keys()].some((key) =>
          sensitiveUrlKeywordPattern.test(key),
        );
      return sensitive ? "[REDACTED LINK]" : url;
    } catch {
      return "[REDACTED LINK]";
    }
  });
}

function redactContextualCodes(text: string): string {
  return text.replace(contextualCodePattern, (candidate, offset: number) => {
    const digits = normalizeCode(candidate);
    if (digits.length < 4 || digits.length > 8) return candidate;

    const start = Math.max(0, offset - 80);
    const end = Math.min(text.length, offset + candidate.length + 80);
    const context = text.slice(start, end);
    return authKeywordPattern.test(context) ? REDACTED : candidate;
  });
}

export function sanitizeEmailText(input: string): string {
  let text = stripHtml(input);
  text = redactSensitiveUrls(text);
  text = text.replace(bearerLikePattern, REDACTED);
  text = text.replace(longDigitPattern, REDACTED);
  text = redactContextualCodes(text);
  return text.replace(/\s+/g, " ").trim();
}

export function truncateSanitized(input: string, maxChars: number): string {
  const sanitized = sanitizeEmailText(input);
  if (sanitized.length <= maxChars) return sanitized;
  return `${sanitized.slice(0, Math.max(0, maxChars - 1)).trimEnd()}…`;
}
