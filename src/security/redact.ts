const REDACTED = '[REDACTED]';

const authKeywordPattern =
  /\b(?:otp|one[- ]?time(?: password| passcode)?|verification|verify|security|sign[- ]?in|sign[- ]?on|2fa|mfa|two[- ]?factor|confirmation|confirm|login|authentication|auth|passcode|pin|code)\b/i;

const sensitiveUrlKeywordPattern =
  /(?:reset|recover|recovery|verify|verification|authenticate|authentication|authorize|authorization|login|signin|sign-in|magic|token|otp|code|password|confirm|2fa|mfa)/i;

const urlPattern = /https?:\/\/[^\s<>"']+/gi;
const longDigitPattern = /\b(?:\d[ -]?){12,19}\b/g;
const contextualCodePattern = /\b\d(?:[\s.-]?\d){3,7}\b/g;
const contextualAlnumCodePattern = /\b[A-Z0-9]{4,12}\b/g;
const bearerLikePattern = /\b(?:bearer\s+)?[A-Za-z0-9_-]{24,}\.[A-Za-z0-9._-]{8,}\b/gi;

function normalizeCode(candidate: string): string {
  return candidate.replace(/[^0-9]/g, '');
}

// Conservative token heuristic: long opaque strings with mixed case+digits, or very long strings.
// Human-readable slugs are typically all-lowercase with no digits, so they rarely match.
function looksLikeToken(s: string): boolean {
  if (s.length >= 16 && (/[0-9]/.test(s) || /[A-Z]/.test(s))) return true;
  if (s.length >= 8 && /[a-z]/.test(s) && /[A-Z]/.test(s) && /[0-9]/.test(s)) return true;
  return false;
}

export function stripHtml(input: string): string {
  return input
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function redactSensitiveUrls(text: string): string {
  return text.replace(urlPattern, (url) => {
    try {
      const parsed = new URL(url);
      const pathSegments = parsed.pathname.split('/').filter(Boolean);
      const sensitiveByKeyword =
        sensitiveUrlKeywordPattern.test(parsed.pathname) ||
        [...parsed.searchParams.keys()].some((key) => sensitiveUrlKeywordPattern.test(key));
      const sensitiveByToken =
        pathSegments.some((seg) => looksLikeToken(seg)) ||
        [...parsed.searchParams.values()].some((val) => looksLikeToken(val)) ||
        (parsed.hash.length > 1 && looksLikeToken(parsed.hash.slice(1)));
      return sensitiveByKeyword || sensitiveByToken ? '[REDACTED LINK]' : url;
    } catch {
      return '[REDACTED LINK]';
    }
  });
}

function redactContextualCodes(text: string): string {
  let result = text.replace(contextualCodePattern, (candidate, offset: number) => {
    const digits = normalizeCode(candidate);
    if (digits.length < 4 || digits.length > 8) return candidate;

    const start = Math.max(0, offset - 80);
    const end = Math.min(text.length, offset + candidate.length + 80);
    const context = text.slice(start, end);
    return authKeywordPattern.test(context) ? REDACTED : candidate;
  });

  result = result.replace(contextualAlnumCodePattern, (candidate, offset: number) => {
    if (/^\d+$/.test(candidate)) return candidate; // pure digits handled above
    const start = Math.max(0, offset - 80);
    const end = Math.min(text.length, offset + candidate.length + 80);
    const context = text.slice(start, end);
    return authKeywordPattern.test(context) ? REDACTED : candidate;
  });

  return result;
}

export function sanitizeEmailText(input: string): string {
  let text = stripHtml(input);
  text = redactSensitiveUrls(text);
  text = text.replace(bearerLikePattern, REDACTED);
  text = text.replace(longDigitPattern, REDACTED);
  text = redactContextualCodes(text);
  return text.replace(/\s+/g, ' ').trim();
}

// Sanitize a mail header value (subject, sender name) and bound its length.
export function sanitizeHeader(input: string, maxChars = 200): string {
  const sanitized = sanitizeEmailText(input);
  return sanitized.length <= maxChars ? sanitized : `${sanitized.slice(0, maxChars - 1).trimEnd()}…`;
}

export function truncateSanitized(input: string, maxChars: number): string {
  const sanitized = sanitizeEmailText(input);
  if (sanitized.length <= maxChars) return sanitized;
  return `${sanitized.slice(0, Math.max(0, maxChars - 1)).trimEnd()}…`;
}
