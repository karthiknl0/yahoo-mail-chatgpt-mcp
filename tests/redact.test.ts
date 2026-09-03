import { describe, expect, it } from 'vitest';
import { sanitizeEmailText, sanitizeHeader, stripHtml, truncateSanitized } from '../src/security/redact.js';

describe('email redaction', () => {
  it('redacts contextual OTP codes', () => {
    expect(sanitizeEmailText('Your OTP is 492811. Do not share it.')).not.toContain('492811');
    expect(sanitizeEmailText('Verification code: 12 34 56')).not.toContain('12 34 56');
    expect(sanitizeEmailText('Security passcode 12-34')).not.toContain('12-34');
  });

  it('does not redact ordinary short numbers without auth context', () => {
    expect(sanitizeEmailText('Invoice total is 2026 rupees')).toContain('2026');
  });

  it('redacts password reset and authentication links', () => {
    const reset = 'Reset here: https://example.com/password/reset?token=supersecret';
    const auth = 'https://example.com/login?code=abcdef123456';
    expect(sanitizeEmailText(reset)).not.toContain('supersecret');
    expect(sanitizeEmailText(reset)).toContain('[REDACTED LINK]');
    expect(sanitizeEmailText(auth)).toBe('[REDACTED LINK]');
  });

  it('redacts long account or card-like digit sequences', () => {
    const output = sanitizeEmailText('Account number: 1234 5678 9012 3456');
    expect(output).not.toContain('1234 5678 9012 3456');
  });

  it('removes active HTML and still redacts OTP text', () => {
    const html = '<style>.x{color:red}</style><script>alert(1)</script><p>Your verification code is <b>654321</b></p>';
    const output = sanitizeEmailText(html);
    expect(output).not.toContain('<script>');
    expect(output).not.toContain('654321');
  });

  it('strips basic HTML safely', () => {
    expect(stripHtml('<p>Hello &amp; goodbye</p>')).toBe('Hello & goodbye');
  });

  it('sanitizes before truncating', () => {
    const output = truncateSanitized(`OTP 123456 ${'x'.repeat(500)}`, 80);
    expect(output.length).toBeLessThanOrEqual(80);
    expect(output).not.toContain('123456');
  });

  it('redacts sign-in keyword contextual codes', () => {
    expect(sanitizeEmailText('Confirm sign-in: 738104')).not.toContain('738104');
    expect(sanitizeEmailText('sign-on attempt — code 291047')).not.toContain('291047');
    expect(sanitizeEmailText('2FA code: 830192')).not.toContain('830192');
  });

  it('redacts mixed alphanumeric one-time codes near auth keywords', () => {
    expect(sanitizeEmailText('Your one-time code: A9F2K1')).not.toContain('A9F2K1');
    expect(sanitizeEmailText('verification token: B3X7YZ')).not.toContain('B3X7YZ');
  });

  it('redacts opaque magic-link path segments', () => {
    const url = 'https://acct.example.com/r/9fJ2kQ8s';
    expect(sanitizeEmailText(`Click here: ${url}`)).toContain('[REDACTED LINK]');
    expect(sanitizeEmailText(`Click here: ${url}`)).not.toContain('9fJ2kQ8s');
  });

  it('redacts token-like URL query values', () => {
    const url = 'https://example.com/u?t=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
    expect(sanitizeEmailText(url)).toContain('[REDACTED LINK]');
    expect(sanitizeEmailText(url)).not.toContain('eyJhbGci');
  });

  it('sanitizeHeader redacts OTP in subject and truncates long values', () => {
    expect(sanitizeHeader('492811 is your verification code')).not.toContain('492811');
    const long = 'x'.repeat(300);
    expect(sanitizeHeader(long).length).toBeLessThanOrEqual(200);
  });
});
