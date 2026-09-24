// PKCE (RFC 7636), S256 only. The "plain" challenge method is never
// accepted -- see docs/adr/0003-pkce-mandatory-s256-only.md -- so this
// module has no code path for it at all, rather than a branch that
// silently trusts an unhashed challenge.
import { createHash, timingSafeEqual } from 'node:crypto';

/** Computes the S256 code_challenge for a given code_verifier. */
export function computeS256Challenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Verifies a token request's code_verifier against the code_challenge
 * recorded when the authorization code was issued. Constant-time so a
 * mismatched challenge can't be distinguished character-by-character via
 * response timing.
 */
export function verifyCodeVerifier(verifier: string, storedChallenge: string): boolean {
  const computed = computeS256Challenge(verifier);
  const a = Buffer.from(computed);
  const b = Buffer.from(storedChallenge);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** RFC 7636 4.1: 43-128 characters from [A-Za-z0-9-._~]. */
export function isValidCodeVerifierFormat(verifier: string): boolean {
  return verifier.length >= 43 && verifier.length <= 128 && /^[A-Za-z0-9\-._~]+$/.test(verifier);
}
