import { Hono } from 'hono';
import { loadConfig } from '@/config';

const config = loadConfig();

export const discoveryRoutes = new Hono();

discoveryRoutes.get('/.well-known/openid-configuration', (c) => {
  const issuer = config.ISSUER;
  return c.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/jwks.json`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    // Never "plain" -- see docs/adr/0003.
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
  });
});
