import { prisma } from '@/db/client';
import { generateOpaqueToken, hashToken } from '@/core/opaqueToken';
import { decideRotation } from '@/core/refreshRotation';

export interface IssueTokenPairInput {
  clientId: string;
  userId: string;
  scope: string;
  familyId: string;
  accessTokenTtlSeconds: number;
  refreshTokenTtlSeconds: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export async function issueTokenPair(input: IssueTokenPairInput): Promise<TokenPair> {
  const accessToken = generateOpaqueToken();
  const refreshToken = generateOpaqueToken();
  const now = Date.now();

  await prisma.$transaction([
    prisma.accessToken.create({
      data: {
        tokenHash: hashToken(accessToken),
        familyId: input.familyId,
        clientId: input.clientId,
        userId: input.userId,
        scope: input.scope,
        expiresAt: new Date(now + input.accessTokenTtlSeconds * 1000),
      },
    }),
    prisma.refreshToken.create({
      data: {
        tokenHash: hashToken(refreshToken),
        familyId: input.familyId,
        clientId: input.clientId,
        userId: input.userId,
        scope: input.scope,
        expiresAt: new Date(now + input.refreshTokenTtlSeconds * 1000),
      },
    }),
  ]);

  return { accessToken, refreshToken };
}

export type RotateResult =
  | ({ ok: true } & TokenPair)
  | { ok: false; error: 'invalid_grant' };

/**
 * Redeems a refresh token: rotates it for a new access/refresh pair, or
 * -- if the presented token was already rotated away once before --
 * treats the presentation as theft and revokes the whole family. See
 * docs/adr/0002.
 */
export async function rotateRefreshToken(
  presentedToken: string,
  clientId: string,
  accessTokenTtlSeconds: number,
  refreshTokenTtlSeconds: number,
): Promise<RotateResult> {
  const tokenHash = hashToken(presentedToken);
  const record = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  const decision = decideRotation(record, new Date());

  if (decision.kind === 'reuse_detected') {
    await revokeFamily(decision.familyId);
    return { ok: false, error: 'invalid_grant' };
  }
  if (decision.kind === 'reject') {
    return { ok: false, error: 'invalid_grant' };
  }
  // decision.kind === 'rotate'; record is non-null by construction of decideRotation.
  if (record === null || record.clientId !== clientId) {
    return { ok: false, error: 'invalid_grant' };
  }

  const newAccessToken = generateOpaqueToken();
  const newRefreshToken = generateOpaqueToken();
  const now = Date.now();

  await prisma.$transaction([
    prisma.refreshToken.update({
      where: { id: record.id },
      data: { replacedByHash: hashToken(newRefreshToken) },
    }),
    prisma.accessToken.create({
      data: {
        tokenHash: hashToken(newAccessToken),
        familyId: record.familyId,
        clientId: record.clientId,
        userId: record.userId,
        scope: record.scope,
        expiresAt: new Date(now + accessTokenTtlSeconds * 1000),
      },
    }),
    prisma.refreshToken.create({
      data: {
        tokenHash: hashToken(newRefreshToken),
        familyId: record.familyId,
        clientId: record.clientId,
        userId: record.userId,
        scope: record.scope,
        expiresAt: new Date(now + refreshTokenTtlSeconds * 1000),
      },
    }),
  ]);

  return { ok: true, accessToken: newAccessToken, refreshToken: newRefreshToken };
}

/** Revokes every access and refresh token sharing familyId. Used on
 *  rotation-reuse detection, an authorization-code replay, and an
 *  explicit logout/revoke request. */
export async function revokeFamily(familyId: string): Promise<void> {
  const now = new Date();
  await prisma.$transaction([
    prisma.refreshToken.updateMany({ where: { familyId, revokedAt: null }, data: { revokedAt: now } }),
    prisma.accessToken.updateMany({ where: { familyId, revokedAt: null }, data: { revokedAt: now } }),
  ]);
}

export interface AccessTokenInfo {
  userId: string;
  clientId: string;
  scope: string;
}

/** Looks up a bearer access token for /userinfo and resource access:
 *  revoked or expired tokens are indistinguishable from never having
 *  existed, on purpose. */
export async function lookupAccessToken(rawToken: string): Promise<AccessTokenInfo | null> {
  const record = await prisma.accessToken.findUnique({ where: { tokenHash: hashToken(rawToken) } });
  if (record === null) return null;
  if (record.revokedAt !== null) return null;
  if (record.expiresAt.getTime() <= Date.now()) return null;
  return { userId: record.userId, clientId: record.clientId, scope: record.scope };
}

/** RFC 7009: revoking either token type revokes the whole family -- the
 *  reasonable interpretation of "log this session out", not just the
 *  one token handed to the endpoint. */
export async function revokeToken(rawToken: string): Promise<void> {
  const tokenHash = hashToken(rawToken);
  const refresh = await prisma.refreshToken.findUnique({ where: { tokenHash } });
  if (refresh !== null) {
    await revokeFamily(refresh.familyId);
    return;
  }
  const access = await prisma.accessToken.findUnique({ where: { tokenHash } });
  if (access !== null) {
    await revokeFamily(access.familyId);
  }
}
