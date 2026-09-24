// Every credential this service hands out over the wire -- authorization
// codes, access tokens, refresh tokens, session cookies -- is a random,
// high-entropy opaque string. Only its SHA-256 hash is ever stored, so a
// database read (a backup, a misconfigured replica, a careless log line
// from a *different* system) cannot be turned back into a usable token.
//
// SHA-256, not argon2/bcrypt: those exist to slow down guessing a
// low-entropy secret a human chose (a password). A 256-bit random token
// has nothing to guess -- brute-forcing it is already infeasible -- so a
// slow hash would only add latency to every single request for no
// security benefit. Password hashing is a different problem, handled
// separately in core/password.ts.
import { createHash, randomBytes } from 'node:crypto';

/** A random 256-bit token, base64url-encoded. */
export function generateOpaqueToken(): string {
  return randomBytes(32).toString('base64url');
}

/** The value actually stored and compared against on lookup. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}
