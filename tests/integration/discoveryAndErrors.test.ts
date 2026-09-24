import { afterAll, describe, expect, it } from 'vitest';
import { app } from '@/server';
import { prisma } from '@/db/client';

const clientId = 'discovery-test-client';
const REDIRECT_URI = 'http://localhost:4000/callback';

afterAll(async () => {
  await prisma.client.deleteMany({ where: { id: clientId } });
  await prisma.$disconnect();
});

describe('GET /.well-known/openid-configuration', () => {
  it('advertises only what this server actually supports', async () => {
    const res = await app.request('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.response_types_supported).toEqual(['code']);
    expect(body.code_challenge_methods_supported).toEqual(['S256']);
    expect(body.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
  });
});

describe('GET /jwks.json', () => {
  it('returns a keys array, generating the first signing key on demand', async () => {
    const res = await app.request('/jwks.json');
    expect(res.status).toBe(200);
    const body = (await res.json()) as { keys: unknown[] };
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
  });
});

describe('GET /authorize error handling', () => {
  it('shows an error page (not a redirect) for an unknown client', async () => {
    const res = await app.request('/authorize?response_type=code&client_id=does-not-exist&redirect_uri=https://x.example.com&scope=openid&code_challenge=' + 'a'.repeat(43) + '&code_challenge_method=S256');
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });

  it('shows an error page (not a redirect) for an unregistered redirect_uri', async () => {
    await prisma.client.upsert({
      where: { id: clientId },
      update: {},
      create: { id: clientId, name: 'Discovery Test Client', type: 'PUBLIC', redirectUris: [REDIRECT_URI] },
    });
    const res = await app.request(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent('https://evil.example.com')}&scope=openid&code_challenge=${'a'.repeat(43)}&code_challenge_method=S256`,
    );
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
  });

  it('redirects with an error for a registered redirect_uri but an unsupported response_type', async () => {
    const res = await app.request(
      `/authorize?response_type=token&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid&code_challenge=${'a'.repeat(43)}&code_challenge_method=S256`,
    );
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get('location')!);
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('error')).toBe('unsupported_response_type');
  });

  it('redirects with an error for the plain PKCE method', async () => {
    const res = await app.request(
      `/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid&code_challenge=${'a'.repeat(43)}&code_challenge_method=plain`,
    );
    expect(res.status).toBe(302);
    const location = new URL(res.headers.get('location')!);
    expect(location.searchParams.get('error')).toBe('invalid_request');
  });
});

describe('POST /userinfo authentication', () => {
  it('rejects a request with no Authorization header', async () => {
    const res = await app.request('/userinfo');
    expect(res.status).toBe(401);
  });

  it('rejects a bearer token that does not exist', async () => {
    const res = await app.request('/userinfo', { headers: { authorization: 'Bearer not-a-real-token' } });
    expect(res.status).toBe(401);
  });
});

describe('POST /token client authentication', () => {
  it('rejects an unknown client_id outright', async () => {
    const form = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'does-not-exist',
      code: 'anything',
      redirect_uri: REDIRECT_URI,
      code_verifier: 'a'.repeat(43),
    });
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'invalid_client' });
  });

  it('rejects an unsupported grant_type', async () => {
    const form = new URLSearchParams({
      grant_type: 'password',
      client_id: clientId,
      username: 'a',
      password: 'b',
    });
    const res = await app.request('/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: form.toString(),
    });
    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({ error: 'unsupported_grant_type' });
  });
});
