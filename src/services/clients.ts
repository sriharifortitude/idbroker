import type { Client } from '@prisma/client';
import { prisma } from '@/db/client';
import { verifyPassword } from '@/core/password';

export function findClient(clientId: string): Promise<Client | null> {
  return prisma.client.findUnique({ where: { id: clientId } });
}

/** CONFIDENTIAL clients only -- a PUBLIC client has no secret to check. */
export async function verifyClientSecret(client: Client, secret: string): Promise<boolean> {
  if (client.secretHash === null) return false;
  return verifyPassword(client.secretHash, secret);
}

/** Exact match only -- see docs/adr on redirect_uri handling. */
export function isRedirectUriAllowed(client: Client, redirectUri: string): boolean {
  return client.redirectUris.includes(redirectUri);
}
