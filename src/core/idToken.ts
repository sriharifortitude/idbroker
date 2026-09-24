import { SignJWT, importJWK, type JWK } from 'jose';

export interface IdTokenClaims {
  issuer: string;
  subject: string; // the user id
  audience: string; // the client_id
  nonce: string | undefined;
  email: string | undefined;
  emailVerified?: boolean;
  authTime?: Date;
  expiresInSeconds: number;
}

export async function signIdToken(privateJwk: JWK, kid: string, claims: IdTokenClaims): Promise<string> {
  const key = await importJWK(privateJwk, 'RS256');
  const payload: Record<string, unknown> = {};
  if (claims.nonce !== undefined) payload.nonce = claims.nonce;
  if (claims.email !== undefined) payload.email = claims.email;
  if (claims.emailVerified !== undefined) payload.email_verified = claims.emailVerified;
  if (claims.authTime !== undefined) payload.auth_time = Math.floor(claims.authTime.getTime() / 1000);

  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', kid })
    .setIssuer(claims.issuer)
    .setSubject(claims.subject)
    .setAudience(claims.audience)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + claims.expiresInSeconds)
    .sign(key);
}
