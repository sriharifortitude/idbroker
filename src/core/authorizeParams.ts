// Validating the /authorize request is split into two phases with
// different consequences on failure, which is the one subtlety in an
// otherwise ordinary parameter check: until redirect_uri is confirmed to
// be one the client actually registered, it cannot be trusted enough to
// redirect the user's browser there -- an attacker-supplied redirect_uri
// is exactly how an open-redirect-flavoured attack on an OAuth server
// works. Once it is confirmed, every later error (bad response_type,
// missing PKCE, unknown scope) is reported *to* that redirect_uri with
// an error= query parameter, per RFC 6749 4.1.2.1.
export interface AuthorizeParams {
  responseType: string | undefined;
  redirectUri: string | undefined;
  scope: string | undefined;
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
}

export interface RegisteredClient {
  redirectUris: string[];
}

export type AuthorizeValidation =
  | { ok: true; scope: string }
  /** Client or redirect_uri could not be confirmed -- show an error
   *  page directly, never redirect anywhere. */
  | { ok: false; redirectable: false; error: string; description: string }
  /** redirect_uri is confirmed legitimate -- report the error there. */
  | { ok: false; redirectable: true; error: string; description: string };

const CODE_CHALLENGE_LENGTH = 43; // base64url(SHA-256) is always this long

export function validateAuthorizeParams(
  params: AuthorizeParams,
  client: RegisteredClient | null,
): AuthorizeValidation {
  if (client === null) {
    return { ok: false, redirectable: false, error: 'invalid_request', description: 'unknown client' };
  }
  if (params.redirectUri === undefined || !client.redirectUris.includes(params.redirectUri)) {
    return {
      ok: false,
      redirectable: false,
      error: 'invalid_request',
      description: 'redirect_uri is not registered for this client',
    };
  }

  if (params.responseType !== 'code') {
    return {
      ok: false,
      redirectable: true,
      error: 'unsupported_response_type',
      description: 'only response_type=code is supported',
    };
  }
  if (params.codeChallengeMethod !== 'S256') {
    return {
      ok: false,
      redirectable: true,
      error: 'invalid_request',
      description: 'code_challenge_method must be S256 (plain is not accepted)',
    };
  }
  if (params.codeChallenge === undefined || params.codeChallenge.length !== CODE_CHALLENGE_LENGTH) {
    return { ok: false, redirectable: true, error: 'invalid_request', description: 'malformed code_challenge' };
  }

  const scopes = (params.scope ?? '').split(' ').filter((s) => s.length > 0);
  if (!scopes.includes('openid')) {
    return {
      ok: false,
      redirectable: true,
      error: 'invalid_scope',
      description: 'scope must include "openid"',
    };
  }

  return { ok: true, scope: scopes.join(' ') };
}
