// RS256 signing keys for ID tokens. RSA (not the smaller/faster Ed25519)
// specifically for interoperability -- RS256 is the one algorithm every
// OIDC relying-party library is guaranteed to support out of the box.
import { randomBytes } from 'node:crypto';
import { exportJWK, generateKeyPair, type JWK } from 'jose';

export interface SigningKeyPair {
  kid: string;
  privateJwk: JWK;
  publicJwk: JWK;
}

export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const kid = randomBytes(16).toString('hex');
  const privateJwk = { ...(await exportJWK(privateKey)), kid, alg: 'RS256', use: 'sig' };
  const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { kid, privateJwk, publicJwk };
}

/**
 * Whether a key should still appear in the published JWKS: an active key
 * always does, and a retired one does until every ID token it could have
 * signed has had time to expire -- otherwise a token issued moments
 * before rotation would fail verification the moment the key list
 * updates.
 */
export function isKeyStillPublishable(
  retiredAt: Date | null,
  now: Date,
  idTokenTtlSeconds: number,
): boolean {
  if (retiredAt === null) return true;
  const graceEnd = retiredAt.getTime() + idTokenTtlSeconds * 1000;
  return now.getTime() < graceEnd;
}
