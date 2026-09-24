import { describe, expect, it } from 'vitest';
import { generateOpaqueToken, hashToken } from '@/core/opaqueToken';

describe('generateOpaqueToken', () => {
  it('produces a 256-bit (43-character base64url) token', () => {
    const token = generateOpaqueToken();
    // 32 raw bytes -> 43 base64url characters, no padding.
    expect(token).toHaveLength(43);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('never repeats across calls', () => {
    const tokens = new Set(Array.from({ length: 1000 }, () => generateOpaqueToken()));
    expect(tokens.size).toBe(1000);
  });
});

describe('hashToken', () => {
  it('is deterministic', () => {
    const token = generateOpaqueToken();
    expect(hashToken(token)).toBe(hashToken(token));
  });

  it('produces a 64-character lowercase hex SHA-256 digest', () => {
    expect(hashToken('anything')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('differs for different inputs', () => {
    expect(hashToken('a')).not.toBe(hashToken('b'));
  });
});
