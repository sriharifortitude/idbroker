import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { app } from '@/server';
import { prisma } from '@/db/client';
import { hashPassword } from '@/core/password';
import { computeS256Challenge } from '@/core/pkce';

const clientId = 'confidential-test-client';
const clientSecret = 'super-secret-value-not-a-real-one';
const REDIRECT_URI = 'http://localhost:4000/callback';
const userEmail = 'confidential-test@example.com';
const password = 'correct horse battery staple';
let userId: string;

async function issueAuthorizationCode(): Promise<{ code: string; verifier: string }> {
  const verifier = 'v'.repeat(50);
  const challenge = computeS256Challenge(verifier);

  const authorizeUrl =
    `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid&code_challenge=${challenge}&code_challenge_method=S256`;
  await app.request(authorizeUrl);

  const loginForm = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    code_challenge: challenge,
    email: userEmail,
    password,
  });
  const loginRes = await app.request('/authorize/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: loginForm.toString(),
  });
  const cookie = /idbroker_session=([^;]+)/.exec(loginRes.headers.get('set-cookie') ?? '')!;

  const consentForm = new URLSearchParams({
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    code_challenge: challenge,
    decision: 'approve',
  });
  const consentRes = await app.request('/authorize/consent', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: `idbroker_session=${cookie[1]}` },
    body: consentForm.toString(),
    redirect: 'manual' as never,
  });
  const location = new URL(consentRes.headers.get('location')!);
  return { code: location.searchParams.get('code')!, verifier };
}

beforeAll(async () => {
  await prisma.client.upsert({
    where: { id: clientId },
    update: {},
    create: {
      id: clientId,
      name: 'Confidential Test Client',
      type: 'CONFIDENTIAL',
      secretHash: await hashPassword(clientSecret),
      redirectUris: [REDIRECT_URI],
    },
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

async function exchange(code: string, verifier: string, authHeader?: string, bodySecret?: string) {
  const params: Record<string, string> = {
    grant_type: 'authorization_code',
    client_id: clientId,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  };
  if (bodySecret !== undefined) params.client_secret = bodySecret;
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (authHeader !== undefined) headers.authorization = authHeader;
  return app.request('/token', { method: 'POST', headers, body: new URLSearchParams(params).toString() });
}

describe('a CONFIDENTIAL client must authenticate to redeem a code', () => {
  it('accepts HTTP Basic client authentication', async () => {
    const { code, verifier } = await issueAuthorizationCode();
    const basic = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
    const res = await exchange(code, verifier, `Basic ${basic}`);
    expect(res.status).toBe(200);
  });

  it('accepts the client_secret in the request body as a fallback', async () => {
    const { code, verifier } = await issueAuthorizationCode();
    const res = await exchange(code, verifier, undefined, clientSecret);
    expect(res.status).toBe(200);
  });

  it('rejects a wrong client_secret', async () => {
    const { code, verifier } = await issueAuthorizationCode();
    const res = await exchange(code, verifier, undefined, 'wrong-secret');
    expect(res.status).toBe(401);
  });

  it('rejects a request with no client_secret at all', async () => {
    const { code, verifier } = await issueAuthorizationCode();
    const res = await exchange(code, verifier);
    expect(res.status).toBe(401);
  });
});
