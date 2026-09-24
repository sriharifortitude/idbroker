# 1. Access and refresh tokens are opaque and DB-backed, not JWTs

Status: accepted — 2026-09-24

## Context

An OAuth authorization server can issue access tokens as self-contained
JWTs (a resource server verifies a signature and trusts the claims, no
call back to the authorization server) or as opaque references (a
resource server, or this server's own `/userinfo`, looks the token up).
A stateless JWT access token is the more common default in OIDC
tutorials, because it lets resource servers scale without a shared
database.

That scalability is bought by giving up the one property that matters
most once a token is loose: the ability to take it back before it
expires. A JWT is valid until its `exp` claim says otherwise, full stop
-- an access token minted with a 5-minute lifetime is a small blast
radius by design, but a refresh token routinely lives for weeks, and
"we cannot revoke a leaked refresh token, only wait for it to expire" is
not an acceptable answer for a service whose entire job is issuing
credentials.

## Decision

Every access token, refresh token, authorization code and browser
session this service issues is a random 256-bit opaque string
(`core/opaqueToken.ts`). Only its SHA-256 hash is ever stored
(`AccessToken.tokenHash`, etc.) or looked up against -- the raw value
exists nowhere at rest, the same property this portfolio's credsweep
scanner checks *other* people's repositories for.

This is the same choice bailey (this portfolio's other credential-
handling service) already made for its own sessions; here it is applied
to every credential a dedicated identity service hands out, not just
one app's login state.

The one JWT this service issues is the ID token -- OIDC specifies that
shape (RFC 7519, signed, verified by the *client*, not looked up by
this server), and its whole purpose is to assert who signed in at a
point in time, which is exactly what a signed, time-bounded, unrevoked-
by-design claim is for. Revoking "who logged in a moment ago" makes no
sense the way revoking "can still make API calls right now" does.

## Consequences

- Every access-token-checking request (`/userinfo`, and any resource
  server that chose to call back to `/userinfo` or delegate lookups
  here) costs a database read. For the scale this service is built for
  -- a portfolio-scale identity provider fronting a handful of
  applications, not a public multi-tenant SaaS -- that cost is
  negligible next to what it buys.
- Revocation is real: `/revoke` (RFC 7009), a stolen refresh token
  caught by rotation reuse detection (ADR 2), and a code replay
  (`services/authCodes.ts`) all take effect on the next request, not at
  the token's original expiry.
- A resource server that is not this service itself cannot verify an
  access token offline -- it has to call `/userinfo` (or a future
  introspection endpoint, not built in v0.1.0) rather than checking a
  signature locally. Stated plainly: this design does not scale to "a
  resource server behind a CDN edge with no path back to the
  authorization server," and is not meant to.
