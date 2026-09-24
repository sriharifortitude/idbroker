import type { JWK } from 'jose';
import { prisma } from '@/db/client';
import { generateSigningKeyPair, isKeyStillPublishable } from '@/core/keys';

export interface ActiveKey {
  kid: string;
  privateJwk: JWK;
}

/**
 * The key that signs new ID tokens: the newest never-retired row, or --
 * on a brand new deployment with no key yet -- one generated and stored
 * on the spot. Key management (docs/adr) is deliberately this simple:
 * no KMS/HSM integration, the private JWK sits in the same database as
 * everything else. Stated as a real limitation, not hidden.
 */
export async function getSigningKeyForIssuing(): Promise<ActiveKey> {
  const existing = await prisma.signingKey.findFirst({
    where: { retiredAt: null },
    orderBy: { createdAt: 'desc' },
  });
  if (existing !== null) {
    return { kid: existing.kid, privateJwk: JSON.parse(existing.privateJwk) as JWK };
  }

  const generated = await generateSigningKeyPair();
  await prisma.signingKey.create({
    data: {
      kid: generated.kid,
      privateJwk: JSON.stringify(generated.privateJwk),
      publicJwk: JSON.stringify(generated.publicJwk),
    },
  });
  return { kid: generated.kid, privateJwk: generated.privateJwk };
}

/** Every key still valid to verify against, for /jwks.json. */
export async function getPublishableJwks(idTokenTtlSeconds: number): Promise<JWK[]> {
  const keys = await prisma.signingKey.findMany({ orderBy: { createdAt: 'desc' } });
  const now = new Date();
  return keys
    .filter((k) => isKeyStillPublishable(k.retiredAt, now, idTokenTtlSeconds))
    .map((k) => JSON.parse(k.publicJwk) as JWK);
}

/** Generates a new active key and retires every previously-active one.
 *  Retired keys keep verifying (getPublishableJwks) until their grace
 *  period elapses; only signing stops immediately. */
export async function rotateSigningKey(): Promise<{ newKid: string }> {
  const generated = await generateSigningKeyPair();
  const now = new Date();
  await prisma.$transaction([
    prisma.signingKey.updateMany({ where: { retiredAt: null }, data: { retiredAt: now } }),
    prisma.signingKey.create({
      data: {
        kid: generated.kid,
        privateJwk: JSON.stringify(generated.privateJwk),
        publicJwk: JSON.stringify(generated.publicJwk),
      },
    }),
  ]);
  return { newKid: generated.kid };
}
