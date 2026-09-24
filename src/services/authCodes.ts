import { randomUUID } from 'node:crypto';
import { prisma } from '@/db/client';
import { generateOpaqueToken, hashToken } from '@/core/opaqueToken';
import { verifyCodeVerifier } from '@/core/pkce';
import { revokeFamily } from '@/services/tokens';

export interface IssueAuthorizationCodeInput {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge: string;
  nonce: string | undefined;
  ttlSeconds: number;
}

export async function issueAuthorizationCode(input: IssueAuthorizationCodeInput): Promise<string> {
  const code = generateOpaqueToken();
  await prisma.authorizationCode.create({
    data: {
      codeHash: hashToken(code),
      clientId: input.clientId,
      userId: input.userId,
      redirectUri: input.redirectUri,
      scope: input.scope,
      codeChallenge: input.codeChallenge,
      nonce: input.nonce ?? null,
      expiresAt: new Date(Date.now() + input.ttlSeconds * 1000),
    },
  });
  return code;
}

export interface RedeemAuthorizationCodeInput {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}

export type RedeemResult =
  | { ok: true; userId: string; scope: string; nonce: string | null; familyId: string }
  | { ok: false; error: 'invalid_grant' };

/**
 * Redeems an authorization code exactly once. Every field the code was
 * issued with (client, redirect_uri, PKCE challenge) is re-checked here,
 * not trusted from the request -- an authorization code is bearer data
 * in transit (a redirect URL) and everything that made the original
 * /authorize request legitimate has to be proven again at exchange time.
 *
 * A code presented a second time is replay, not a benign retry: per the
 * OAuth 2.0 Security BCP, every token the first redemption produced is
 * revoked.
 */
export async function redeemAuthorizationCode(input: RedeemAuthorizationCodeInput): Promise<RedeemResult> {
  const codeHash = hashToken(input.code);
  const record = await prisma.authorizationCode.findUnique({ where: { codeHash } });
  if (record === null) return { ok: false, error: 'invalid_grant' };

  if (record.usedAt !== null) {
    if (record.issuedFamilyId !== null) {
      await revokeFamily(record.issuedFamilyId);
    }
    return { ok: false, error: 'invalid_grant' };
  }

  if (record.expiresAt.getTime() <= Date.now()) return { ok: false, error: 'invalid_grant' };
  if (record.clientId !== input.clientId) return { ok: false, error: 'invalid_grant' };
  if (record.redirectUri !== input.redirectUri) return { ok: false, error: 'invalid_grant' };
  if (!verifyCodeVerifier(input.codeVerifier, record.codeChallenge)) return { ok: false, error: 'invalid_grant' };

  const familyId = randomUUID();
  await prisma.authorizationCode.update({
    where: { id: record.id },
    data: { usedAt: new Date(), issuedFamilyId: familyId },
  });

  return { ok: true, userId: record.userId, scope: record.scope, nonce: record.nonce, familyId };
}
