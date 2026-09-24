import { describe, expect, it } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { generateSigningKeyPair } from '@/core/keys';
import { signIdToken } from '@/core/idToken';

describe('signIdToken', () => {
  it('produces a token verifiable with the matching public key, carrying the standard claims', async () => {
    const { kid, privateJwk, publicJwk } = await generateSigningKeyPair();
    const jwt = await signIdToken(privateJwk, kid, {
      issuer: 'https://idbroker.example.com',
      subject: 'user-123',
      audience: 'client-abc',
      nonce: 'n-0S6_WzA2Mj',
      email: undefined,
      expiresInSeconds: 3600,
    });

    const publicKey = await importJWK(publicJwk, 'RS256');
    const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
      issuer: 'https://idbroker.example.com',
      audience: 'client-abc',
    });

    expect(protectedHeader.kid).toBe(kid);
    expect(payload.sub).toBe('user-123');
    expect(payload.nonce).toBe('n-0S6_WzA2Mj');
    expect(payload.iat).toBeTypeOf('number');
    expect(payload.exp).toBeTypeOf('number');
  });

  it('omits optional claims entirely when not provided, rather than including them as null', async () => {
    const { kid, privateJwk, publicJwk } = await generateSigningKeyPair();
    const jwt = await signIdToken(privateJwk, kid, {
      issuer: 'https://idbroker.example.com',
      subject: 'user-123',
      audience: 'client-abc',
      nonce: undefined,
      email: undefined,
      expiresInSeconds: 3600,
    });
    const publicKey = await importJWK(publicJwk, 'RS256');
    const { payload } = await jwtVerify(jwt, publicKey);
    expect('nonce' in payload).toBe(false);
    expect('email' in payload).toBe(false);
  });

  it('fails verification against a different key pair entirely', async () => {
    const signer = await generateSigningKeyPair();
    const other = await generateSigningKeyPair();
    const jwt = await signIdToken(signer.privateJwk, signer.kid, {
      issuer: 'https://idbroker.example.com',
      subject: 'user-123',
      audience: 'client-abc',
      nonce: undefined,
      email: undefined,
      expiresInSeconds: 3600,
    });
    const wrongPublicKey = await importJWK(other.publicJwk, 'RS256');
    await expect(jwtVerify(jwt, wrongPublicKey)).rejects.toThrow();
  });
});
