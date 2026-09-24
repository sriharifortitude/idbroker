import { describe, expect, it } from 'vitest';
import { SignJWT, importJWK, jwtVerify } from 'jose';
import { generateSigningKeyPair, isKeyStillPublishable } from '@/core/keys';

describe('generateSigningKeyPair', () => {
  it('produces a key pair that can sign and verify a JWT', async () => {
    const { kid, privateJwk, publicJwk } = await generateSigningKeyPair();
    const privateKey = await importJWK(privateJwk, 'RS256');
    const publicKey = await importJWK(publicJwk, 'RS256');

    const jwt = await new SignJWT({ hello: 'world' })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuedAt()
      .sign(privateKey);

    const { payload } = await jwtVerify(jwt, publicKey);
    expect(payload.hello).toBe('world');
  });

  it('gives each key its own kid', async () => {
    const a = await generateSigningKeyPair();
    const b = await generateSigningKeyPair();
    expect(a.kid).not.toBe(b.kid);
  });

  it('marks both JWKs as RS256 signing keys', async () => {
    const { privateJwk, publicJwk } = await generateSigningKeyPair();
    expect(privateJwk.alg).toBe('RS256');
    expect(privateJwk.use).toBe('sig');
    expect(publicJwk.alg).toBe('RS256');
    expect(publicJwk.use).toBe('sig');
  });
});

describe('isKeyStillPublishable', () => {
  const now = new Date('2026-01-15T12:00:00Z');
  const ttl = 3600; // 1 hour

  it('is always publishable when never retired', () => {
    expect(isKeyStillPublishable(null, now, ttl)).toBe(true);
  });

  it('is still publishable just inside the grace window after retirement', () => {
    const retiredAt = new Date('2026-01-15T11:30:00Z'); // 30 min ago
    expect(isKeyStillPublishable(retiredAt, now, ttl)).toBe(true);
  });

  it('is not publishable once the grace window has fully elapsed', () => {
    const retiredAt = new Date('2026-01-15T10:00:00Z'); // 2 hours ago
    expect(isKeyStillPublishable(retiredAt, now, ttl)).toBe(false);
  });

  it('is not publishable at the exact instant the grace window ends', () => {
    const retiredAt = new Date(now.getTime() - ttl * 1000);
    expect(isKeyStillPublishable(retiredAt, now, ttl)).toBe(false);
  });
});
