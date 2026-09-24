import { Hono, type Context } from 'hono';
import type { Client } from '@prisma/client';
import { loadConfig } from '@/config';
import { findClient, verifyClientSecret } from '@/services/clients';
import { redeemAuthorizationCode } from '@/services/authCodes';
import { issueTokenPair, rotateRefreshToken } from '@/services/tokens';
import { getSigningKeyForIssuing } from '@/services/keys';
import { signIdToken } from '@/core/idToken';
import { prisma } from '@/db/client';

const config = loadConfig();

export const tokenRoutes = new Hono();

function tokenError(c: Context, error: string, status: 400 | 401 = 400) {
  return c.json({ error }, status);
}

type ClientAuthResult = { ok: true; client: Client } | { ok: false };

/** Confidential clients present a secret (HTTP Basic, the standard
 *  place, or the body as a fallback); public clients present none and
 *  are not asked for one -- PKCE is what proves this token request came
 *  from the same party that started the authorization, not a client
 *  secret a public client could never actually keep. */
async function authenticateClient(
  clientId: string,
  authHeader: string | undefined,
  bodySecret: string | undefined,
): Promise<ClientAuthResult> {
  const client = await findClient(clientId);
  if (client === null) return { ok: false };
  if (client.type === 'PUBLIC') return { ok: true, client };

  let secret = bodySecret;
  if (authHeader?.startsWith('Basic ') === true) {
    const decoded = Buffer.from(authHeader.slice('Basic '.length), 'base64').toString('utf8');
    const [, presented] = decoded.split(':');
    secret = presented;
  }
  if (secret === undefined) return { ok: false };
  const valid = await verifyClientSecret(client, secret);
  return valid ? { ok: true, client } : { ok: false };
}

tokenRoutes.post('/token', async (c) => {
  const form = await c.req.parseBody();
  const grantType = asOptionalString(form.grant_type) ?? '';
  const clientId = asOptionalString(form.client_id) ?? '';

  const auth = await authenticateClient(clientId, c.req.header('Authorization'), asOptionalString(form.client_secret));
  if (!auth.ok) return tokenError(c, 'invalid_client', 401);
  const client = auth.client;

  if (grantType === 'authorization_code') {
    const code = asOptionalString(form.code);
    const redirectUri = asOptionalString(form.redirect_uri);
    const codeVerifier = asOptionalString(form.code_verifier);
    if (code === undefined || redirectUri === undefined || codeVerifier === undefined) {
      return tokenError(c, 'invalid_request');
    }

    const redeemed = await redeemAuthorizationCode({ code, clientId: client.id, redirectUri, codeVerifier });
    if (!redeemed.ok) return tokenError(c, 'invalid_grant');

    const pair = await issueTokenPair({
      clientId: client.id,
      userId: redeemed.userId,
      scope: redeemed.scope,
      familyId: redeemed.familyId,
      accessTokenTtlSeconds: config.ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTtlSeconds: config.REFRESH_TOKEN_TTL_SECONDS,
    });

    const idToken = await maybeIssueIdToken(redeemed.scope, redeemed.userId, client.id, redeemed.nonce ?? undefined);

    return c.json({
      access_token: pair.accessToken,
      refresh_token: pair.refreshToken,
      token_type: 'Bearer',
      expires_in: config.ACCESS_TOKEN_TTL_SECONDS,
      scope: redeemed.scope,
      ...(idToken !== undefined ? { id_token: idToken } : {}),
    });
  }

  if (grantType === 'refresh_token') {
    const refreshToken = asOptionalString(form.refresh_token);
    if (refreshToken === undefined) return tokenError(c, 'invalid_request');

    const rotated = await rotateRefreshToken(
      refreshToken,
      client.id,
      config.ACCESS_TOKEN_TTL_SECONDS,
      config.REFRESH_TOKEN_TTL_SECONDS,
    );
    if (!rotated.ok) return tokenError(c, 'invalid_grant');

    return c.json({
      access_token: rotated.accessToken,
      refresh_token: rotated.refreshToken,
      token_type: 'Bearer',
      expires_in: config.ACCESS_TOKEN_TTL_SECONDS,
    });
  }

  return tokenError(c, 'unsupported_grant_type');
});

async function maybeIssueIdToken(
  scope: string,
  userId: string,
  clientId: string,
  nonce: string | undefined,
): Promise<string | undefined> {
  if (!scope.split(' ').includes('openid')) return undefined;
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (user === null) return undefined;
  const { kid, privateJwk } = await getSigningKeyForIssuing();
  return signIdToken(privateJwk, kid, {
    issuer: config.ISSUER,
    subject: userId,
    audience: clientId,
    nonce,
    email: scope.split(' ').includes('email') ? user.email : undefined,
    expiresInSeconds: config.ID_TOKEN_TTL_SECONDS,
  });
}

function asOptionalString(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}
