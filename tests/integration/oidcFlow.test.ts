import { randomBytes } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { app } from '@/server';
import { prisma } from '@/db/client';
import { hashPassword } from '@/core/password';
import { computeS256Challenge } from '@/core/pkce';

const REDIRECT_URI = 'http://localhost:4000/callback';
const clientId = 'flow-test-client';
let userId: string;
const userEmail = 'flow-test@example.com';
const password = 'correct horse battery staple';

function verifier(): string {
  return randomBytes(48).toString('base64url'); // > 43 chars, valid format
}

/** Extracts a cookie's value from a Set-Cookie header. */
function extractCookie(response: Response, name: string): string {
  const raw = response.headers.get('set-cookie') ?? '';
  const match = new RegExp(`${name}=([^;]+)`).exec(raw);
  if (match === null) throw new Error(`no ${name} cookie in response`);
  return `${name}=${match[1]}`;
}

async function loginAndConsent(pkceVerifier: string, scope = 'openid profile email') {
  const challenge = computeS256Challenge(pkceVerifier);
  const authorizeUrl =
    `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=${encodeURIComponent(scope)}&state=xyz&code_challenge=${challenge}&code_challenge_method=S256&nonce=abc123`;

  const getRes = await app.request(authorizeUrl);
  expect(getRes.status).toBe(200);

  const loginForm = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 'xyz',
    code_challenge: challenge,
    nonce: 'abc123',
    email: userEmail,
    password,
  });
  const loginRes = await app.request('/authorize/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: loginForm.toString(),
  });
  expect(loginRes.status).toBe(200);
  const cookie = extractCookie(loginRes, 'idbroker_session');

  const consentForm = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope,
    state: 'xyz',
    code_challenge: challenge,
    nonce: 'abc123',
    decision: 'approve',
  });
  const consentRes = await app.request('/authorize/consent', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
    body: consentForm.toString(),
    redirect: 'manual' as never,
  });
  expect(consentRes.status).toBe(302);
  const location = new URL(consentRes.headers.get('location')!);
  expect(location.searchParams.get('state')).toBe('xyz');
  const code = location.searchParams.get('code');
  expect(code).not.toBeNull();
  return code!;
}

async function exchangeCode(code: string, pkceVerifier: string) {
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: pkceVerifier,
  });
  const res = await app.request('/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form.toString(),
  });
  return res;
}

beforeAll(async () => {
  await prisma.client.upsert({
    where: { id: clientId },
    update: {},
    create: { id: clientId, name: 'Flow Test Client', type: 'PUBLIC', redirectUris: [REDIRECT_URI] },
  });
  const user = await prisma.user.upsert({
    where: { email: userEmail },
    update: {},
    create: { email: userEmail, passwordHash: await hashPassword(password) },
  });
  userId = user.id;
});

afterAll(async () => {
  await prisma.accessToken.deleteMany({ where: { clientId } });
  await prisma.refreshToken.deleteMany({ where: { clientId } });
  await prisma.authorizationCode.deleteMany({ where: { clientId } });
  await prisma.session.deleteMany({ where: { userId } });
  await prisma.client.delete({ where: { id: clientId } });
  await prisma.user.delete({ where: { id: userId } });
  await prisma.$disconnect();
});

describe('the full authorization code + PKCE flow', () => {
  it('issues access, refresh and ID tokens, and the ID token verifies against the published JWKS', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);
    const tokenRes = await exchangeCode(code, pkceVerifier);
    expect(tokenRes.status).toBe(200);
    const body = (await tokenRes.json()) as Record<string, unknown>;
    expect(body.access_token).toBeTypeOf('string');
    expect(body.refresh_token).toBeTypeOf('string');
    expect(body.id_token).toBeTypeOf('string');

    const jwksRes = await app.request('/jwks.json');
    const { keys } = (await jwksRes.json()) as { keys: Array<{ kid: string }> };
    expect(keys.length).toBeGreaterThan(0);
    const key = await importJWK(keys[0]! as never, 'RS256');
    const { payload } = await jwtVerify(body.id_token as string, key);
    expect(payload.sub).toBe(userId);
    expect(payload.nonce).toBe('abc123');
    expect(payload.email).toBe(userEmail);
  });

  it('rejects a code_verifier that does not match the original code_challenge', async () => {
    const code = await loginAndConsent(verifier());
    const res = await exchangeCode(code, verifier()); // a different, unrelated verifier
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'invalid_grant' });
  });

  it('serves the userinfo endpoint for a valid access token', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);
    const tokenRes = await exchangeCode(code, pkceVerifier);
    const { access_token } = (await tokenRes.json()) as { access_token: string };

    const res = await app.request('/userinfo', { headers: { authorization: `Bearer ${access_token}` } });
    expect(res.status).toBe(200);
    const info = (await res.json()) as Record<string, unknown>;
    expect(info.sub).toBe(userId);
    expect(info.email).toBe(userEmail);
  });

  it('rejects an authorization code presented a second time, and revokes the tokens the first exchange issued', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);

    const first = await exchangeCode(code, pkceVerifier);
    expect(first.status).toBe(200);
    const { access_token } = (await first.json()) as { access_token: string };

    const replay = await exchangeCode(code, pkceVerifier);
    expect(replay.status).toBe(400);
    expect(await replay.json()).toEqual({ error: 'invalid_grant' });

    // the token the legitimate first exchange issued must now be dead too
    const userinfoRes = await app.request('/userinfo', { headers: { authorization: `Bearer ${access_token}` } });
    expect(userinfoRes.status).toBe(401);
  });
});

describe('refresh token rotation', () => {
  async function refresh(refreshToken: string) {
    const form = new URLSearchParams({ grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken });
    return app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
  }

  it('issues a new token pair and invalidates the presented refresh token', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);
    const first = (await (await exchangeCode(code, pkceVerifier)).json()) as { refresh_token: string };

    const rotated = await refresh(first.refresh_token);
    expect(rotated.status).toBe(200);
    const second = (await rotated.json()) as { access_token: string; refresh_token: string };
    expect(second.refresh_token).not.toBe(first.refresh_token);

    // the new access token actually works
    const info = await app.request('/userinfo', { headers: { authorization: `Bearer ${second.access_token}` } });
    expect(info.status).toBe(200);

    // the original refresh token cannot be used a second time
    const reused = await refresh(first.refresh_token);
    expect(reused.status).toBe(400);
  });

  it('detects reuse of an already-rotated refresh token and revokes the whole family, including the legitimate current token', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);
    const first = (await (await exchangeCode(code, pkceVerifier)).json()) as {
      access_token: string;
      refresh_token: string;
    };

    const rotated = await refresh(first.refresh_token);
    const second = (await rotated.json()) as { access_token: string; refresh_token: string };

    // an attacker (or a bug) presents the OLD, already-rotated token again
    const reuse = await refresh(first.refresh_token);
    expect(reuse.status).toBe(400);

    // the family is now fully revoked: even the legitimate, most-recent
    // access token from the honest rotation no longer works
    const info = await app.request('/userinfo', { headers: { authorization: `Bearer ${second.access_token}` } });
    expect(info.status).toBe(401);

    // and the legitimate current refresh token can no longer rotate either
    const nextRotate = await refresh(second.refresh_token);
    expect(nextRotate.status).toBe(400);
  });
});

describe('POST /revoke', () => {
  it('revoking a refresh token invalidates its whole family', async () => {
    const pkceVerifier = verifier();
    const code = await loginAndConsent(pkceVerifier);
    const tokens = (await (await exchangeCode(code, pkceVerifier)).json()) as {
      access_token: string;
      refresh_token: string;
    };

    const revokeRes = await app.request('/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: tokens.refresh_token }).toString(),
    });
    expect(revokeRes.status).toBe(200);

    const info = await app.request('/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
    expect(info.status).toBe(401);
  });

  it('returns 200 for a token that does not exist, rather than leaking whether it did', async () => {
    const res = await app.request('/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: 'not-a-real-token' }).toString(),
    });
    expect(res.status).toBe(200);
  });
});
