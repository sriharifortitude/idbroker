import { describe, expect, it } from 'vitest';
import { computeS256Challenge, isValidCodeVerifierFormat, verifyCodeVerifier } from '@/core/pkce';

describe('computeS256Challenge', () => {
  it('matches the RFC 7636 appendix B worked example', () => {
    // https://www.rfc-editor.org/rfc/rfc7636#appendix-B
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(computeS256Challenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
});

describe('verifyCodeVerifier', () => {
  it('accepts the verifier that produces the stored challenge', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    const challenge = computeS256Challenge(verifier);
    expect(verifyCodeVerifier(verifier, challenge)).toBe(true);
  });

  it('rejects a verifier that does not match', () => {
    const challenge = computeS256Challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
    expect(verifyCodeVerifier('some-other-verifier-that-is-long-enough-1234567890', challenge)).toBe(false);
  });

  it('rejects a challenge of a different length without throwing', () => {
    expect(verifyCodeVerifier('anything-at-all-1234567890123456789012345', 'short')).toBe(false);
  });
});

describe('isValidCodeVerifierFormat', () => {
  it('accepts a 43-character unreserved-character string', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(43))).toBe(true);
  });

  it('accepts a 128-character string (the maximum)', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(128))).toBe(true);
  });

  it('rejects anything shorter than 43 characters', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(42))).toBe(false);
  });

  it('rejects anything longer than 128 characters', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(129))).toBe(false);
  });

  it('rejects a character outside [A-Za-z0-9-._~]', () => {
    expect(isValidCodeVerifierFormat('a'.repeat(42) + '+')).toBe(false);
  });
});
