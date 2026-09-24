import { prisma } from '@/db/client';
import { generateOpaqueToken, hashToken } from '@/core/opaqueToken';

export async function createSession(userId: string, ttlSeconds: number): Promise<string> {
  const token = generateOpaqueToken();
  await prisma.session.create({
    data: { tokenHash: hashToken(token), userId, expiresAt: new Date(Date.now() + ttlSeconds * 1000) },
  });
  return token;
}

export async function lookupSession(rawToken: string): Promise<{ userId: string } | null> {
  const record = await prisma.session.findUnique({ where: { tokenHash: hashToken(rawToken) } });
  if (record === null) return null;
  if (record.expiresAt.getTime() <= Date.now()) return null;
  return { userId: record.userId };
}

export async function deleteSession(rawToken: string): Promise<void> {
  await prisma.session.deleteMany({ where: { tokenHash: hashToken(rawToken) } });
}
