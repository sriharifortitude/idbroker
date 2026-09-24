import { describe, expect, it } from 'vitest';
import { validateAuthorizeParams } from '@/core/authorizeParams';

const client = { redirectUris: ['https://app.example.com/callback'] };
const validChallenge = 'a'.repeat(43);

function params(overrides: Partial<Parameters<typeof validateAuthorizeParams>[0]> = {}) {
  return {
    responseType: 'code',
    redirectUri: 'https://app.example.com/callback',
    scope: 'openid profile',
    codeChallenge: validChallenge,
    codeChallengeMethod: 'S256',
    ...overrides,
  };
}

describe('validateAuthorizeParams', () => {
  it('accepts a well-formed request and normalises the scope string', () => {
    const result = validateAuthorizeParams(params({ scope: '  openid  profile  ' }), client);
    expect(result).toEqual({ ok: true, scope: 'openid profile' });
  });

  it('is not redirectable when the client is unknown', () => {
    const result = validateAuthorizeParams(params(), null);
    expect(result).toMatchObject({ ok: false, redirectable: false });
  });

  it('is not redirectable when redirect_uri is not registered -- exact match only', () => {
    const result = validateAuthorizeParams(params({ redirectUri: 'https://app.example.com/callback/' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: false });
  });

  it('is not redirectable when redirect_uri is missing entirely', () => {
    const result = validateAuthorizeParams(params({ redirectUri: undefined }), client);
    expect(result).toMatchObject({ ok: false, redirectable: false });
  });

  it('is redirectable once redirect_uri is confirmed, for an unsupported response_type', () => {
    const result = validateAuthorizeParams(params({ responseType: 'token' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'unsupported_response_type' });
  });

  it('rejects the plain PKCE method, redirectably', () => {
    const result = validateAuthorizeParams(params({ codeChallengeMethod: 'plain' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'invalid_request' });
  });

  it('rejects a missing code_challenge', () => {
    const result = validateAuthorizeParams(params({ codeChallenge: undefined }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'invalid_request' });
  });

  it('rejects a code_challenge of the wrong length', () => {
    const result = validateAuthorizeParams(params({ codeChallenge: 'tooshort' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'invalid_request' });
  });

  it('rejects a scope that does not include openid', () => {
    const result = validateAuthorizeParams(params({ scope: 'profile email' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'invalid_scope' });
  });

  it('rejects an empty scope', () => {
    const result = validateAuthorizeParams(params({ scope: '' }), client);
    expect(result).toMatchObject({ ok: false, redirectable: true, error: 'invalid_scope' });
  });
});
